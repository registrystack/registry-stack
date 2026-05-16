// SPDX-License-Identifier: Apache-2.0
//! Entity query tests over in-memory DataFusion tables.

use std::sync::Arc;

use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::table_name;
use registry_relay::query::{
    EntityCollectionQuery, EntityFilter, EntityFilterOp, EntityQueryEngine,
};
use serde_json::json;
use tempfile::TempDir;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("query_entity.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
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
              nullable: true
            - name: region_code
              type: string
              nullable: true
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
            - name: given_name
              type: string
              nullable: true
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
        relationships:
          - name: members
            kind: has_many
            target: individual
            foreign_key: household_id
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
              ops: [eq, in, gte, lte, between]
          allowed_expansions: [members]
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: given_name
        relationships:
          - name: household
            kind: belongs_to
            target: household
            foreign_key: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
        api:
          default_limit: 1
          max_limit: 1000
          allowed_filters:
            - field: household_id
              ops: [eq]
          allowed_expansions: [household]

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    path
}

async fn query_engine() -> EntityQueryEngine {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let cfg = config::load(&config_path).expect("config loads");
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("entity registry compiles"));
    let ctx = Arc::new(SessionContext::new());

    let schema = Arc::new(Schema::new(vec![
        Field::new("household_id", DataType::Utf8, false),
        Field::new("region_code", DataType::Utf8, true),
        Field::new("internal_note", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["hh-1", "hh-2"])),
            Arc::new(StringArray::from(vec!["north", "south"])),
            Arc::new(StringArray::from(vec!["private-a", "private-b"])),
        ],
    )
    .expect("record batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("households_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register table");

    let individual_schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("household_id", DataType::Utf8, true),
        Field::new("given_name", DataType::Utf8, true),
    ]));
    let individual_batch = RecordBatch::try_new(
        Arc::clone(&individual_schema),
        vec![
            Arc::new(StringArray::from(vec!["p-1", "p-2", "p-3", "p-4", "p-5"])),
            Arc::new(StringArray::from(vec![
                Some("hh-1"),
                Some("hh-1"),
                Some("hh-2"),
                None,
                Some("hh-missing"),
            ])),
            Arc::new(StringArray::from(vec![
                Some("Ada"),
                Some("Ben"),
                Some("Cy"),
                Some("Dee"),
                Some("Eli"),
            ])),
        ],
    )
    .expect("individual record batch");
    let individual_table =
        MemTable::try_new(individual_schema, vec![vec![individual_batch]]).expect("mem table");
    let resource: ResourceId = id("individuals_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(individual_table))
        .expect("register individual table");

    EntityQueryEngine::new(ctx, registry)
}

#[tokio::test]
async fn collection_projects_public_field_names() {
    let engine = query_engine().await;
    let rows = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new()
                .with_fields(["id", "region"])
                .with_limit(10),
        )
        .await
        .expect("read collection")
        .rows;

    assert_eq!(
        rows,
        vec![
            json!({"id": "hh-1", "region": "north"}),
            json!({"id": "hh-2", "region": "south"}),
        ]
    );
    assert!(rows[0].get("household_id").is_none());
    assert!(rows[0].get("region_code").is_none());
    assert!(rows[0].get("internal_note").is_none());
}

#[tokio::test]
async fn collection_paginates_after_primary_key_position() {
    let engine = query_engine().await;
    let first_page = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new()
                .with_fields(["region"])
                .with_limit(1),
        )
        .await
        .expect("read first page");

    assert_eq!(first_page.rows, vec![json!({"region": "north"})]);
    assert_eq!(first_page.next_primary_key, Some(json!("hh-1")));

    let second_page = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new()
                .with_fields(["region"])
                .with_limit(1)
                .with_after_primary_key(json!("hh-1")),
        )
        .await
        .expect("read second page");

    assert_eq!(second_page.rows, vec![json!({"region": "south"})]);
    assert_eq!(second_page.next_primary_key, None);
}

#[tokio::test]
async fn single_record_filters_by_entity_primary_key() {
    let engine = query_engine().await;
    let row = engine
        .read_record(
            "social_registry",
            "household",
            json!("hh-2"),
            None,
            Vec::new(),
        )
        .await
        .expect("read record")
        .expect("matching row");

    assert_eq!(row.value, json!({"id": "hh-2", "region": "south"}));
}

#[tokio::test]
async fn collection_supports_exposed_base_field_eq_filter() {
    let engine = query_engine().await;
    let rows = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new().with_filter(EntityFilter::eq("region", "north")),
        )
        .await
        .expect("read collection")
        .rows;

    assert_eq!(rows, vec![json!({"id": "hh-1", "region": "north"})]);
}

#[tokio::test]
async fn collection_supports_allowed_in_filter() {
    let engine = query_engine().await;
    let rows = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new().with_filter(EntityFilter::with_op(
                "region",
                EntityFilterOp::In,
                json!(["north", "missing"]),
            )),
        )
        .await
        .expect("read collection")
        .rows;

    assert_eq!(rows, vec![json!({"id": "hh-1", "region": "north"})]);
}

#[tokio::test]
async fn collection_supports_allowed_range_filters() {
    let engine = query_engine().await;
    let gte_rows = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new().with_filter(EntityFilter::with_op(
                "region",
                EntityFilterOp::Gte,
                "south",
            )),
        )
        .await
        .expect("read gte")
        .rows;
    assert_eq!(gte_rows, vec![json!({"id": "hh-2", "region": "south"})]);

    let lte_rows = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new().with_filter(EntityFilter::with_op(
                "region",
                EntityFilterOp::Lte,
                "north",
            )),
        )
        .await
        .expect("read lte")
        .rows;
    assert_eq!(lte_rows, vec![json!({"id": "hh-1", "region": "north"})]);

    let between_rows = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new().with_filter(EntityFilter::with_op(
                "region",
                EntityFilterOp::Between,
                json!(["north", "south"]),
            )),
        )
        .await
        .expect("read between")
        .rows;
    assert_eq!(
        between_rows,
        vec![
            json!({"id": "hh-1", "region": "north"}),
            json!({"id": "hh-2", "region": "south"}),
        ]
    );
}

#[tokio::test]
async fn collection_rejects_unallowed_filter_operator() {
    let engine = query_engine().await;
    let error = engine
        .read_collection(
            "social_registry",
            "individual",
            EntityCollectionQuery::new().with_filter(EntityFilter::with_op(
                "household_id",
                EntityFilterOp::In,
                json!(["hh-1", "hh-2"]),
            )),
        )
        .await
        .expect_err("operator rejected");

    assert_eq!(error.code(), "filter.not_allowed");
}

#[tokio::test]
async fn collection_expands_has_many_with_target_default_limit() {
    let engine = query_engine().await;
    let rows = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new()
                .with_filter(EntityFilter::eq("region", "north"))
                .with_expansions(["members"]),
        )
        .await
        .expect("read collection")
        .rows;

    assert_eq!(
        rows,
        vec![json!({
            "id": "hh-1",
            "region": "north",
            "members": [
                {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"}
            ],
            "_expansion": {"members": {"truncated": true}}
        })]
    );
}

#[tokio::test]
async fn single_record_expands_belongs_to() {
    let engine = query_engine().await;
    let row = engine
        .read_record(
            "social_registry",
            "individual",
            json!("p-1"),
            None,
            vec!["household".to_string()],
        )
        .await
        .expect("read record")
        .expect("matching row");

    assert_eq!(
        row.value,
        json!({
            "id": "p-1",
            "household_id": "hh-1",
            "given_name": "Ada",
            "household": {"id": "hh-1", "region": "north"}
        })
    );
}

#[tokio::test]
async fn belongs_to_relationship_endpoint_returns_unknown_resource_for_null_or_dangling_fk() {
    let engine = query_engine().await;

    let null_fk = engine
        .read_relationship("social_registry", "individual", json!("p-4"), "household")
        .await
        .expect_err("null FK is not a target resource");
    assert_eq!(null_fk.code(), "schema.unknown_resource");

    let dangling_fk = engine
        .read_relationship("social_registry", "individual", json!("p-5"), "household")
        .await
        .expect_err("dangling FK is not a target resource");
    assert_eq!(dangling_fk.code(), "schema.unknown_resource");
}

#[tokio::test]
async fn has_many_relationship_endpoint_paginates_target_rows() {
    let engine = query_engine().await;
    let first_page = engine
        .read_relationship_page(
            "social_registry",
            "household",
            json!("hh-1"),
            "members",
            registry_relay::query::RelationshipPageQuery::new(),
        )
        .await
        .expect("read first relationship page");

    assert_eq!(
        first_page.value,
        json!([
            {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"}
        ])
    );
    assert_eq!(first_page.next_primary_key, Some(json!("p-1")));

    let second_page = engine
        .read_relationship_page(
            "social_registry",
            "household",
            json!("hh-1"),
            "members",
            registry_relay::query::RelationshipPageQuery::new()
                .with_after_primary_key(json!("p-1")),
        )
        .await
        .expect("read second relationship page");

    assert_eq!(
        second_page.value,
        json!([
            {"id": "p-2", "household_id": "hh-1", "given_name": "Ben"}
        ])
    );
    assert_eq!(second_page.next_primary_key, None);
}

#[tokio::test]
async fn unsupported_nested_and_unallowed_expansions_are_rejected() {
    let engine = query_engine().await;

    let nested = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new().with_expansions(["members.household"]),
        )
        .await
        .expect_err("nested expansion rejected");
    assert_eq!(nested.code(), "filter.unsupported_op");

    let unallowed = engine
        .read_collection(
            "social_registry",
            "household",
            EntityCollectionQuery::new().with_expansions(["household"]),
        )
        .await
        .expect_err("unallowed expansion rejected");
    assert_eq!(unallowed.code(), "filter.not_allowed");
}

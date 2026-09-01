// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::contract::{
    BoundaryOperator, ComparisonOperator, ConstraintSource, FieldTypeSource, Operation,
    UniqueWhenPredicate, ValidTimeRole,
};
use crate::model::{
    CompiledAction, CompiledActionEffect, CompiledActionInventory, CompiledActionMutation,
    CompiledActionTargetUse, CompiledActionTargetUseSource, CompiledChangeRequestEffect,
    CompiledChangeRequestMutation, CompiledEntity,
};
use crate::physical_names::{
    hex_prefix, spatial_candidate_view_name, spatial_geometry_column_name,
    spatial_geometry_index_name, PhysicalNameInventory,
};

const RECORD_ID_COLUMN: &str = "record_id";
pub(crate) const POSTGIS_EXTENSION_SCHEMA: &str = "registry_spatial_ext";
pub(crate) const SPATIAL_BBOX_FUNCTION_NAME: &str = "spatial_bbox_geometry";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdlStatementKind {
    Schema,
    Table,
    Column,
    View,
    Function,
    Reference,
    Constraint,
    Index,
    RowSecurity,
    Policy,
    Grant,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TablePrivilege {
    Select,
    Insert,
    Update,
}

impl TablePrivilege {
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCommand {
    Select,
    Insert,
    Update,
}

impl PolicyCommand {
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdlPolicyRole {
    #[default]
    Public,
    Runtime,
    SpatialBbox,
}

impl DdlPolicyRole {
    pub(crate) fn is_public(value: &Self) -> bool {
        *value == Self::Public
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlPolicy {
    pub name: String,
    pub command: PolicyCommand,
    pub access_profile: String,
    #[serde(default, skip_serializing_if = "DdlPolicyRole::is_public")]
    pub applies_to: DdlPolicyRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub using_expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_expression: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdlObjectOwner {
    #[default]
    Migration,
    SpatialBbox,
}

impl DdlObjectOwner {
    pub(crate) fn is_migration(value: &Self) -> bool {
        *value == Self::Migration
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlTable {
    pub entity_id: String,
    pub physical_name: String,
    pub runtime_privileges: BTreeSet<TablePrivilege>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub spatial_bbox_privileges: BTreeSet<TablePrivilege>,
    pub policies: Vec<DdlPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlView {
    pub id: String,
    pub schema: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "DdlObjectOwner::is_migration")]
    pub owner: DdlObjectOwner,
    pub runtime_privileges: BTreeSet<TablePrivilege>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlFunction {
    pub id: String,
    pub schema: String,
    pub name: String,
    pub arguments: String,
    pub runtime_execute: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub spatial_bbox_execute: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlStatement {
    pub id: String,
    pub kind: DdlStatementKind,
    pub sql: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlInventory {
    pub requires_btree_gist: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_postgis: bool,
    pub statements: Vec<DdlStatement>,
    pub tables: Vec<DdlTable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub views: Vec<DdlView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<DdlFunction>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl DdlInventory {
    pub fn script(&self) -> String {
        let mut output = String::new();
        for statement in &self.statements {
            output.push_str(&statement.sql);
            output.push_str(";\n");
        }
        output
    }
}

pub(crate) fn generate_ddl_with_actions(
    entities: &BTreeMap<String, CompiledEntity>,
    names: &PhysicalNameInventory,
    actions: &CompiledActionInventory,
) -> DdlInventory {
    let mut statements = vec![DdlStatement {
        id: "schema.registry_data".to_owned(),
        kind: DdlStatementKind::Schema,
        sql: "CREATE SCHEMA IF NOT EXISTS registry_data".to_owned(),
    }];
    for schema in ["registry_source", "registry_derived", "registry_context"] {
        statements.push(DdlStatement {
            id: format!("schema.{schema}"),
            kind: DdlStatementKind::Schema,
            sql: format!("CREATE SCHEMA IF NOT EXISTS {schema}"),
        });
    }
    statements.push(DdlStatement {
        id: "function.registry_context.evaluation_date".to_owned(),
        kind: DdlStatementKind::Function,
        sql: "CREATE OR REPLACE FUNCTION registry_context.evaluation_date()
              RETURNS date
              LANGUAGE sql
              STABLE
              SECURITY INVOKER
              AS $registry_server_function$
                  SELECT NULLIF(current_setting('registry.evaluation_date', true), '')::date
              $registry_server_function$"
            .to_owned(),
    });
    let requires_postgis = requires_postgis(entities);
    if requires_postgis {
        statements.push(spatial_bbox_function_statement());
    }

    for entity in entities.values() {
        let mut columns = vec![
            "record_id uuid NOT NULL".to_owned(),
            "record_revision bigint NOT NULL DEFAULT 1 CHECK (record_revision > 0)".to_owned(),
            "record_lifecycle text NOT NULL DEFAULT 'active' CHECK (record_lifecycle IN ('active', 'tombstoned'))".to_owned(),
            "created_at timestamptz NOT NULL DEFAULT transaction_timestamp()".to_owned(),
            "updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()".to_owned(),
            "active_package_revision text NOT NULL DEFAULT NULLIF(current_setting('registry.active_package_revision', true), '') CHECK (active_package_revision <> '')".to_owned(),
            "PRIMARY KEY (record_id)".to_owned(),
        ];
        for field in entity.fields.values() {
            columns.push(column_definition_for_entity(entity, field));
        }
        for field_id in spatial_projection_fields(entity) {
            columns.push(spatial_projection_column_definition(entity, &field_id));
        }
        statements.push(DdlStatement {
            id: format!("entity.{}.table", entity.id),
            kind: DdlStatementKind::Table,
            sql: format!(
                "CREATE TABLE registry_data.{} ({})",
                quote_identifier(&entity.physical_table),
                columns.join(", ")
            ),
        });
    }

    for entity in entities.values() {
        let entity_names = &names.entities[&entity.id];
        if entity.temporal.is_some() {
            statements.push(DdlStatement {
                id: format!("entity.{}.constraint.temporal-order", entity.id),
                kind: DdlStatementKind::Constraint,
                sql: temporal_order_constraint_sql(entity),
            });
        }
        for field in entity.fields.values() {
            if let FieldTypeSource::Reference { target, .. } = &field.field_type {
                let constraint_name = derived_reference_name(entity_names, &field.id);
                statements.push(DdlStatement {
                    id: format!("entity.{}.field.{}.reference", entity.id, field.id),
                    kind: DdlStatementKind::Reference,
                    sql: format!(
                        "ALTER TABLE registry_data.{} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES registry_data.{} (record_id) ON DELETE RESTRICT",
                        quote_identifier(&entity.physical_table),
                        quote_identifier(constraint_name),
                        quote_identifier(&field.physical_name),
                        quote_identifier(&entities[target].physical_table),
                    ),
                });
            }
        }

        for (constraint_id, constraint) in &entity.constraints {
            let kind = if matches!(constraint, ConstraintSource::Unique { when: Some(_), .. }) {
                DdlStatementKind::Index
            } else {
                DdlStatementKind::Constraint
            };
            statements.push(DdlStatement {
                id: format!("entity.{}.constraint.{constraint_id}", entity.id),
                kind,
                sql: constraint_sql(entity, entity_names, constraint_id, constraint),
            });
        }

        for (index_id, fields) in &entity.indexes {
            let columns = fields
                .iter()
                .map(|field| quote_identifier(&entity.fields[field].physical_name))
                .collect::<Vec<_>>()
                .join(", ");
            statements.push(DdlStatement {
                id: format!("entity.{}.index.{index_id}", entity.id),
                kind: DdlStatementKind::Index,
                sql: format!(
                    "CREATE INDEX {} ON registry_data.{} ({columns})",
                    quote_identifier(&entity_names.indexes[index_id]),
                    quote_identifier(&entity.physical_table),
                ),
            });
        }
        for field_id in spatial_projection_fields(entity) {
            statements.push(spatial_projection_statements(entity, &field_id).create_index);
        }
    }

    let mut tables = Vec::new();
    let mut views = Vec::new();
    let mut functions = vec![DdlFunction {
        id: "registry_context.evaluation_date".to_owned(),
        schema: "registry_context".to_owned(),
        name: "evaluation_date".to_owned(),
        arguments: String::new(),
        runtime_execute: true,
        spatial_bbox_execute: false,
    }];
    if requires_postgis {
        functions.push(DdlFunction {
            id: format!("registry_context.{SPATIAL_BBOX_FUNCTION_NAME}"),
            schema: "registry_context".to_owned(),
            name: SPATIAL_BBOX_FUNCTION_NAME.to_owned(),
            arguments: String::new(),
            runtime_execute: true,
            spatial_bbox_execute: true,
        });
    }
    for entity in entities.values() {
        let runtime_privileges = runtime_privileges(entity, entities, actions);
        let policies = policies(entity, entities, actions);
        let table = quote_identifier(&entity.physical_table);
        statements.push(DdlStatement {
            id: format!("entity.{}.rls.enable", entity.id),
            kind: DdlStatementKind::RowSecurity,
            sql: format!("ALTER TABLE registry_data.{table} ENABLE ROW LEVEL SECURITY"),
        });
        statements.push(DdlStatement {
            id: format!("entity.{}.rls.force", entity.id),
            kind: DdlStatementKind::RowSecurity,
            sql: format!("ALTER TABLE registry_data.{table} FORCE ROW LEVEL SECURITY"),
        });
        for policy in &policies {
            if policy.applies_to == DdlPolicyRole::Public {
                statements.push(DdlStatement {
                    id: format!("entity.{}.policy.{}", entity.id, policy.name),
                    kind: DdlStatementKind::Policy,
                    sql: policy_sql(&table, policy, None),
                });
            }
        }
        tables.push(DdlTable {
            entity_id: entity.id.clone(),
            physical_name: entity.physical_table.clone(),
            runtime_privileges,
            spatial_bbox_privileges: spatial_bbox_table_privileges(entity),
            policies,
        });
        if let Some(candidate_view) = spatial_candidate_view_statement(entity) {
            statements.push(candidate_view);
            views.push(DdlView {
                id: format!("entity.{}.spatial-candidates", entity.id),
                schema: "registry_context".to_owned(),
                name: spatial_candidate_view_name(&entity.id),
                owner: DdlObjectOwner::SpatialBbox,
                runtime_privileges: BTreeSet::from([TablePrivilege::Select]),
            });
        }
    }

    // Derived SQL may read any compiled registry_source relation. Install the
    // complete logical source layer before installing any dependent view.
    for entity in entities.values() {
        let source_view = quote_identifier(&entity.source_relation.sql_name);
        let mut source_columns = vec![format!(
            "{RECORD_ID_COLUMN} AS {}",
            quote_identifier(&entity.canonical_id.sql_name)
        )];
        for field_id in &entity.source_relation.stored_fields {
            let field = entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == *field_id)
                .expect("compiled source relation names only stored fields");
            source_columns.push(format!(
                "{} AS {}",
                quote_identifier(&field.physical_name),
                quote_identifier(&field.logical.sql_name)
            ));
        }
        statements.push(DdlStatement {
            id: format!("entity.{}.source-view", entity.id),
            kind: DdlStatementKind::View,
            sql: format!(
                "CREATE VIEW registry_source.{source_view}
                 WITH (security_invoker=true, security_barrier=true)
                 AS SELECT {}
                    FROM registry_data.{}
                   WHERE record_lifecycle = 'active'",
                source_columns.join(", "),
                quote_identifier(&entity.physical_table),
            ),
        });
        views.push(DdlView {
            id: format!("entity.{}.source", entity.id),
            schema: "registry_source".to_owned(),
            name: entity.source_relation.sql_name.clone(),
            owner: DdlObjectOwner::Migration,
            runtime_privileges: BTreeSet::from([TablePrivilege::Select]),
        });
    }

    for entity in entities.values() {
        for relation in entity.derived_relations.values() {
            let derived_view_name =
                derived_view_name(&entity.source_relation.sql_name, &relation.id);
            let view = quote_identifier(&derived_view_name);
            let sql = std::str::from_utf8(&relation.sql_bytes)
                .expect("derived SQL asset was UTF-8 validated")
                .trim()
                .trim_end_matches(';');
            let key = quote_identifier(&relation.key_field.replace('-', "_"));
            // `$` is outside the closed logical identifier grammar, so these
            // wrapper-only names cannot collide with an authored SQL output.
            let canonical_key = quote_identifier("__registry$derived$key");
            let cardinality = quote_identifier("__registry$derived$cardinality");
            let mut columns = vec![format!(
                "{} AS {}",
                canonical_key,
                quote_identifier(&entity.canonical_id.sql_name)
            )];
            for field_id in &relation.fields {
                let field = entity
                    .derived_fields
                    .get(field_id)
                    .expect("compiled relation names only derived fields");
                columns.push(format!(
                    "{}::{} AS {}",
                    quote_identifier(&field.logical.sql_name),
                    sql_type(&field.logical.field_type),
                    quote_identifier(&field.logical.sql_name)
                ));
            }
            statements.push(DdlStatement {
                id: format!("entity.{}.derived.{}.view", entity.id, relation.id),
                kind: DdlStatementKind::View,
                sql: format!(
                    "CREATE VIEW registry_derived.{view}
                     WITH (security_invoker=true, security_barrier=true)
                     AS SELECT {}
                        FROM (
                            SELECT canonical_derived.*,
                                   count(*) OVER (PARTITION BY canonical_derived.{canonical_key}) AS {cardinality}
                              FROM (
                                  SELECT trusted_derived.*,
                                         trusted_derived.{key}::{} AS {canonical_key}
                                    FROM ({sql}) AS trusted_derived
                              ) AS canonical_derived
                        ) AS checked_derived
                       WHERE CASE
                           WHEN {canonical_key} IS NOT NULL AND {cardinality} = 1 THEN true
                           -- PostgreSQL has no scalar ASSERT. This row-dependent
                           -- expression raises one stable, value-free error for
                           -- a null or duplicate canonical key.
                           ELSE 1 / ({cardinality} - {cardinality}) = 0
                       END",
                    columns.join(", "),
                    sql_type(&entity.canonical_id.field_type),
                ),
            });
            views.push(DdlView {
                id: format!("entity.{}.derived.{}", entity.id, relation.id),
                schema: "registry_derived".to_owned(),
                name: derived_view_name,
                owner: DdlObjectOwner::Migration,
                runtime_privileges: BTreeSet::from([TablePrivilege::Select]),
            });
        }
    }

    DdlInventory {
        requires_btree_gist: entities.values().any(|entity| {
            entity
                .constraints
                .values()
                .any(|value| matches!(value, ConstraintSource::TemporalNonOverlap { .. }))
        }),
        requires_postgis,
        statements,
        tables,
        views,
        functions,
    }
}

fn requires_postgis(entities: &BTreeMap<String, CompiledEntity>) -> bool {
    entities
        .values()
        .any(|entity| !spatial_projection_fields(entity).is_empty())
}

pub(crate) fn spatial_projection_fields(entity: &CompiledEntity) -> BTreeSet<String> {
    let Some(geojson) = entity.geojson.as_ref() else {
        return BTreeSet::new();
    };
    entity
        .access_profiles
        .values()
        .filter(|profile| profile.operations.contains(&Operation::List))
        .filter(|profile| {
            profile
                .spatial_queries
                .as_ref()
                .and_then(|spatial| spatial.bbox.as_ref())
                .is_some()
        })
        .map(|_| geojson.geometry_field.clone())
        .collect()
}

fn ordinary_policy_role(entity: &CompiledEntity) -> DdlPolicyRole {
    if spatial_projection_fields(entity).is_empty() {
        DdlPolicyRole::Public
    } else {
        DdlPolicyRole::Runtime
    }
}

#[cfg_attr(
    not(feature = "runtime"),
    allow(dead_code, reason = "runtime package planning consumes this helper")
)]
pub(crate) fn drop_spatial_bbox_function_statement() -> DdlStatement {
    DdlStatement {
        id: format!("function.registry_context.{SPATIAL_BBOX_FUNCTION_NAME}.drop"),
        kind: DdlStatementKind::Function,
        sql: format!("DROP FUNCTION IF EXISTS registry_context.{SPATIAL_BBOX_FUNCTION_NAME}()"),
    }
}

pub(crate) fn spatial_bbox_function_statement() -> DdlStatement {
    DdlStatement {
        id: format!("function.registry_context.{SPATIAL_BBOX_FUNCTION_NAME}"),
        kind: DdlStatementKind::Function,
        sql: format!(
            "CREATE OR REPLACE FUNCTION registry_context.{SPATIAL_BBOX_FUNCTION_NAME}()
             RETURNS {POSTGIS_EXTENSION_SCHEMA}.geometry
             LANGUAGE sql
             STABLE
             SECURITY INVOKER
             AS $registry_server_function$
                 SELECT CASE
                     WHEN west = east AND south = north THEN
                         {POSTGIS_EXTENSION_SCHEMA}.ST_SetSRID(
                             {POSTGIS_EXTENSION_SCHEMA}.ST_MakePoint(west, south),
                             4326
                         )::{POSTGIS_EXTENSION_SCHEMA}.geometry
                     WHEN west = east OR south = north THEN
                         {POSTGIS_EXTENSION_SCHEMA}.ST_MakeLine(
                             {POSTGIS_EXTENSION_SCHEMA}.ST_SetSRID(
                                 {POSTGIS_EXTENSION_SCHEMA}.ST_MakePoint(west, south),
                                 4326
                             ),
                             {POSTGIS_EXTENSION_SCHEMA}.ST_SetSRID(
                                 {POSTGIS_EXTENSION_SCHEMA}.ST_MakePoint(east, north),
                                 4326
                             )
                         )::{POSTGIS_EXTENSION_SCHEMA}.geometry
                     ELSE
                         {POSTGIS_EXTENSION_SCHEMA}.ST_MakeEnvelope(west, south, east, north, 4326)
                 END
                   FROM (
                     SELECT NULLIF(current_setting('registry.bbox_west', true), '')::double precision AS west,
                            NULLIF(current_setting('registry.bbox_south', true), '')::double precision AS south,
                            NULLIF(current_setting('registry.bbox_east', true), '')::double precision AS east,
                            NULLIF(current_setting('registry.bbox_north', true), '')::double precision AS north
                   ) AS registry_bbox
             $registry_server_function$"
        ),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpatialProjectionStatements {
    pub add_column: DdlStatement,
    pub create_index: DdlStatement,
    pub drop_index: DdlStatement,
    pub drop_column: DdlStatement,
}

pub(crate) fn spatial_projection_statements(
    entity: &CompiledEntity,
    field_id: &str,
) -> SpatialProjectionStatements {
    assert!(
        matches!(
            entity.fields[field_id].field_type,
            FieldTypeSource::Crs84Point { .. }
        ),
        "spatial projections are generated only for CRS84 point fields"
    );
    let column_name = spatial_geometry_column_name(&entity.id, field_id);
    let index_name = spatial_geometry_index_name(&entity.id, field_id);
    let table = quote_identifier(&entity.physical_table);
    let column = quote_identifier(&column_name);
    let index = quote_identifier(&index_name);
    SpatialProjectionStatements {
        add_column: DdlStatement {
            id: format!("entity.{}.field.{field_id}.spatial-column.add", entity.id),
            kind: DdlStatementKind::Column,
            sql: format!(
                "ALTER TABLE registry_data.{table} ADD COLUMN {}",
                spatial_projection_column_definition(entity, field_id)
            ),
        },
        create_index: DdlStatement {
            id: format!("entity.{}.field.{field_id}.spatial-index.create", entity.id),
            kind: DdlStatementKind::Index,
            sql: spatial_projection_index_sql(entity, field_id),
        },
        drop_index: DdlStatement {
            id: format!("entity.{}.field.{field_id}.spatial-index.drop", entity.id),
            kind: DdlStatementKind::Index,
            sql: format!("DROP INDEX IF EXISTS registry_data.{index}"),
        },
        drop_column: DdlStatement {
            id: format!("entity.{}.field.{field_id}.spatial-column.drop", entity.id),
            kind: DdlStatementKind::Column,
            sql: format!("ALTER TABLE registry_data.{table} DROP COLUMN IF EXISTS {column}"),
        },
    }
}

fn spatial_projection_column_definition(entity: &CompiledEntity, field_id: &str) -> String {
    let source = quote_identifier(&entity.fields[field_id].physical_name);
    let column = quote_identifier(&spatial_geometry_column_name(&entity.id, field_id));
    format!(
        "{column} {POSTGIS_EXTENSION_SCHEMA}.geometry(Point,4326)
         GENERATED ALWAYS AS (
             CASE
                 WHEN {source} IS NULL THEN NULL
                 ELSE {POSTGIS_EXTENSION_SCHEMA}.ST_SetSRID(
                     {POSTGIS_EXTENSION_SCHEMA}.ST_MakePoint(
                         ({source} -> 'coordinates' ->> 0)::double precision,
                         ({source} -> 'coordinates' ->> 1)::double precision
                     ),
                     4326
                 )::{POSTGIS_EXTENSION_SCHEMA}.geometry(Point,4326)
             END
         ) STORED"
    )
}

fn spatial_projection_index_sql(entity: &CompiledEntity, field_id: &str) -> String {
    let table = quote_identifier(&entity.physical_table);
    let column = quote_identifier(&spatial_geometry_column_name(&entity.id, field_id));
    let index = quote_identifier(&spatial_geometry_index_name(&entity.id, field_id));
    format!(
        "CREATE INDEX {index} ON registry_data.{table} USING gist ({column}) WHERE {column} IS NOT NULL"
    )
}

pub(crate) fn derived_view_name(source_relation: &str, derived_relation: &str) -> String {
    let slug = derived_relation.replace('-', "_");
    let candidate = format!("{source_relation}__{slug}");
    if candidate.len() <= 63 {
        return candidate;
    }
    let digest = Sha256::digest(format!("registry-server/derived-view/{candidate}").as_bytes());
    format!("{}_{}", &candidate[..46], hex_prefix(&digest, 8))
}

#[cfg(feature = "runtime")]
pub(crate) fn add_column_statement(
    entity: &CompiledEntity,
    field: &crate::model::CompiledField,
) -> DdlStatement {
    DdlStatement {
        id: format!("entity.{}.field.{}.column", entity.id, field.id),
        kind: DdlStatementKind::Column,
        sql: format!(
            "ALTER TABLE registry_data.{} ADD COLUMN {}",
            quote_identifier(&entity.physical_table),
            column_definition_for_entity(entity, field)
        ),
    }
}

fn column_definition_for_entity(
    entity: &CompiledEntity,
    field: &crate::model::CompiledField,
) -> String {
    let nullable_when_tombstoned =
        entity.change_request.is_some() && !request_row_boundary_fields(entity).contains(&field.id);
    column_definition(field, nullable_when_tombstoned)
}

fn request_row_boundary_fields(entity: &CompiledEntity) -> BTreeSet<String> {
    let mut fields = entity
        .access_profiles
        .values()
        .flat_map(|profile| {
            profile
                .row_boundaries
                .iter()
                .map(|boundary| boundary.field.clone())
        })
        .collect::<BTreeSet<_>>();
    if let Some(request) = &entity.change_request {
        for grant in &request.presence_grants {
            fields.extend(
                grant
                    .request_row_boundaries
                    .iter()
                    .map(|boundary| boundary.field.clone()),
            );
        }
    }
    fields
}

fn column_definition(
    field: &crate::model::CompiledField,
    nullable_when_tombstoned: bool,
) -> String {
    let identifier = quote_identifier(&field.physical_name);
    let mut column = format!("{} {}", identifier, sql_type(&field.field_type));
    if field.required && !nullable_when_tombstoned {
        column.push_str(" NOT NULL");
    }
    if field.required && nullable_when_tombstoned {
        column.push_str(" CHECK (record_lifecycle = 'tombstoned' OR ");
        column.push_str(&identifier);
        column.push_str(" IS NOT NULL)");
    }
    if let Some(check) = field_check(&identifier, &field.field_type) {
        column.push_str(" CHECK (");
        column.push_str(&check);
        column.push(')');
    }
    column
}

fn spatial_bbox_table_privileges(entity: &CompiledEntity) -> BTreeSet<TablePrivilege> {
    if spatial_projection_fields(entity).is_empty() {
        BTreeSet::new()
    } else {
        BTreeSet::from([TablePrivilege::Select])
    }
}

fn runtime_privileges(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    actions: &CompiledActionInventory,
) -> BTreeSet<TablePrivilege> {
    let operations = entity
        .access_profiles
        .values()
        .flat_map(|profile| profile.operations.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut privileges = BTreeSet::new();
    if operations.iter().any(|operation| {
        matches!(
            operation,
            Operation::Get
                | Operation::Lookup
                | Operation::List
                | Operation::Batch
                | Operation::Revisions
                | Operation::Snapshot
        )
    }) || path_select_entities(entities).contains(&entity.id)
    {
        privileges.insert(TablePrivilege::Select);
    }
    if operations.contains(&Operation::Create) {
        privileges.insert(TablePrivilege::Insert);
        privileges.insert(TablePrivilege::Select);
    }
    if operations
        .iter()
        .any(|operation| matches!(operation, Operation::Patch | Operation::Tombstone))
    {
        privileges.insert(TablePrivilege::Update);
    }
    if entity
        .change_request
        .as_ref()
        .is_some_and(|request| !request.presence_grants.is_empty())
    {
        privileges.insert(TablePrivilege::Select);
    }
    if entity.change_request.is_some()
        && operations.iter().any(|operation| {
            matches!(
                operation,
                Operation::SubmitRequest
                    | Operation::ApproveRequest
                    | Operation::RejectRequest
                    | Operation::RequestRevision
                    | Operation::ReviseRequest
                    | Operation::CancelRequest
                    | Operation::ApplyRequest
            )
        })
    {
        privileges.insert(TablePrivilege::Select);
        privileges.insert(TablePrivilege::Update);
    }
    for request in entities
        .values()
        .filter_map(|entity| entity.change_request.as_ref())
    {
        for effect in &request.effects {
            if effect.target.entity_id != entity.id {
                continue;
            }
            privileges.insert(TablePrivilege::Select);
            match effect.operation {
                Operation::Create => {
                    privileges.insert(TablePrivilege::Insert);
                }
                Operation::Patch => {
                    privileges.insert(TablePrivilege::Update);
                }
                _ => {}
            }
        }
    }
    for action in &actions.actions {
        for target_use in &action.target_uses {
            if target_use.entity_id != entity.id {
                continue;
            }
            privileges.insert(TablePrivilege::Select);
            match target_use.operation {
                Operation::Create => {
                    privileges.insert(TablePrivilege::Insert);
                }
                Operation::Patch => {
                    privileges.insert(TablePrivilege::Update);
                }
                Operation::Invoke if target_use.fields.is_empty() => {
                    privileges.insert(TablePrivilege::Update);
                }
                _ => {}
            }
        }
    }
    privileges
}

fn policies(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    actions: &CompiledActionInventory,
) -> Vec<DdlPolicy> {
    let mut policies = Vec::new();
    for profile in entity.access_profiles.values() {
        for command in [
            PolicyCommand::Select,
            PolicyCommand::Insert,
            PolicyCommand::Update,
        ] {
            if !profile_supports_command(&profile.operations, command) {
                continue;
            }
            let authority = policy_authority_expression(entity, profile);
            let (using_expression, check_expression) = match command {
                PolicyCommand::Select => {
                    let action_context_guard = if entity.change_request.is_some() {
                        format!(
                            " AND {} IS NULL",
                            change_request_action_context_expression()
                        )
                    } else {
                        String::new()
                    };
                    let lifecycle_expression = request_get_lifecycle_expression(entity, profile);
                    (
                        Some(format!(
                            "({authority}) AND ({lifecycle_expression}){action_context_guard}"
                        )),
                        None,
                    )
                }
                PolicyCommand::Insert => (
                    None,
                    Some(format!("({authority}) AND record_lifecycle = 'active'")),
                ),
                PolicyCommand::Update => {
                    let lifecycle_check = if profile.operations.contains(&Operation::Tombstone) {
                        "record_lifecycle IN ('active', 'tombstoned')"
                    } else {
                        "record_lifecycle = 'active'"
                    };
                    (
                        Some(format!("({authority}) AND record_lifecycle = 'active'")),
                        Some(format!("({authority}) AND {lifecycle_check}")),
                    )
                }
            };
            policies.push(DdlPolicy {
                name: policy_name(&entity.id, &profile.id, command),
                command,
                access_profile: profile.id.clone(),
                applies_to: ordinary_policy_role(entity),
                using_expression,
                check_expression,
            });
        }
        if profile.operations.contains(&Operation::Create)
            && !profile_supports_command(&profile.operations, PolicyCommand::Select)
        {
            let authority = policy_authority_expression(entity, profile);
            policies.push(DdlPolicy {
                name: create_returning_policy_name(&entity.id, &profile.id),
                command: PolicyCommand::Select,
                access_profile: profile.id.clone(),
                applies_to: ordinary_policy_role(entity),
                using_expression: Some(format!(
                    "({authority}) AND record_lifecycle = 'active' AND {} = NULLIF(current_setting('registry.created_entity_id', true), '') AND record_id = NULLIF(current_setting('registry.created_record_id', true), '')::uuid",
                    quote_literal(&entity.id)
                )),
                check_expression: None,
            });
        }
    }
    policies.extend(change_request_action_policies_for_table(entity));
    policies.extend(change_request_presence_policies_for_table(entity, entities));
    policies.extend(read_path_policies_for_table(entity, entities));
    policies.extend(change_request_target_policies_for_table(entity, entities));
    policies.extend(immediate_action_target_policies_for_table(entity, actions));
    policies.extend(spatial_bbox_select_policies(entity));
    policies
}

fn request_get_lifecycle_expression(
    entity: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
) -> String {
    if entity.change_request.is_some() && profile.operations.contains(&Operation::Get) {
        format!(
            "record_lifecycle = 'active' OR (
                record_lifecycle = 'tombstoned'
                AND EXISTS (
                    SELECT 1
                      FROM registry_internal.registry_request_state AS cr_state
                     WHERE cr_state.request_entity_id = {}
                       AND cr_state.request_id = record_id
                       AND cr_state.state IN ('rejected', 'canceled', 'applied')
                       AND cr_state.detail_erased_at IS NOT NULL
                )
            )",
            quote_literal(&entity.id)
        )
    } else {
        "record_lifecycle = 'active'".to_owned()
    }
}

fn spatial_bbox_select_policies(entity: &CompiledEntity) -> Vec<DdlPolicy> {
    let mut policies = Vec::new();
    let Some(geojson) = entity.geojson.as_ref() else {
        return policies;
    };
    for profile in entity.access_profiles.values() {
        if !profile.operations.contains(&Operation::List) {
            continue;
        }
        let Some(bbox) = profile
            .spatial_queries
            .as_ref()
            .and_then(|spatial| spatial.bbox.as_ref())
        else {
            continue;
        };
        let geometry_field = &geojson.geometry_field;
        let spatial = spatial_bbox_predicate(entity, geometry_field, bbox);
        policies.push(DdlPolicy {
            name: spatial_bbox_policy_name(&entity.id, &profile.id),
            command: PolicyCommand::Select,
            access_profile: profile.id.clone(),
            applies_to: DdlPolicyRole::SpatialBbox,
            using_expression: Some(format!(
                "({}) AND record_lifecycle = 'active' AND ({spatial})",
                policy_authority_expression(entity, profile),
            )),
            check_expression: None,
        });
    }
    policies
}

pub(crate) fn spatial_candidate_view_statement(entity: &CompiledEntity) -> Option<DdlStatement> {
    let predicates = spatial_candidate_predicates(entity);
    if predicates.is_empty() {
        return None;
    }
    Some(DdlStatement {
        id: format!("entity.{}.spatial-candidates-view", entity.id),
        kind: DdlStatementKind::View,
        sql: format!(
            "CREATE VIEW registry_context.{}
             WITH (security_invoker=false, security_barrier=true)
             AS SELECT record_id AS id
                  FROM registry_data.{}
                 WHERE {}",
            quote_identifier(&spatial_candidate_view_name(&entity.id)),
            quote_identifier(&entity.physical_table),
            predicates.join(" OR "),
        ),
    })
}

#[cfg(feature = "runtime")]
pub(crate) fn drop_spatial_candidate_view_statement(
    entity: &CompiledEntity,
) -> Option<DdlStatement> {
    spatial_candidate_view_statement(entity).map(|_| DdlStatement {
        id: format!("entity.{}.spatial-candidates-view.drop", entity.id),
        kind: DdlStatementKind::View,
        sql: format!(
            "DROP VIEW IF EXISTS registry_context.{}",
            quote_identifier(&spatial_candidate_view_name(&entity.id)),
        ),
    })
}

fn spatial_candidate_predicates(entity: &CompiledEntity) -> Vec<String> {
    let Some(geojson) = entity.geojson.as_ref() else {
        return Vec::new();
    };
    let geometry_field = &geojson.geometry_field;
    entity
        .access_profiles
        .values()
        .filter_map(|profile| {
            let bbox = profile
                .spatial_queries
                .as_ref()
                .and_then(|spatial| spatial.bbox.as_ref())?;
            if !profile.operations.contains(&Operation::List) {
                return None;
            }
            Some(format!(
                "(({}) AND record_lifecycle = 'active' AND ({}))",
                policy_authority_expression(entity, profile),
                spatial_bbox_predicate(entity, geometry_field, bbox),
            ))
        })
        .collect()
}

fn spatial_bbox_predicate(
    entity: &CompiledEntity,
    geometry_field: &str,
    bbox: &crate::contract::SpatialBboxGrantSource,
) -> String {
    let geometry = quote_identifier(&spatial_geometry_column_name(&entity.id, geometry_field));
    let source = quote_identifier(&entity.fields[geometry_field].physical_name);
    let west = "NULLIF(current_setting('registry.bbox_west', true), '')::numeric";
    let south = "NULLIF(current_setting('registry.bbox_south', true), '')::numeric";
    let east = "NULLIF(current_setting('registry.bbox_east', true), '')::numeric";
    let north = "NULLIF(current_setting('registry.bbox_north', true), '')::numeric";
    format!(
        "{geometry} IS NOT NULL
         AND ({east} - {west}) BETWEEN 0 AND {}
         AND ({north} - {south}) BETWEEN 0 AND {}
         AND {geometry} OPERATOR({POSTGIS_EXTENSION_SCHEMA}.&&) registry_context.{SPATIAL_BBOX_FUNCTION_NAME}()
         AND {POSTGIS_EXTENSION_SCHEMA}.ST_Intersects({geometry}, registry_context.{SPATIAL_BBOX_FUNCTION_NAME}())
         AND ({source} -> 'coordinates' ->> 0)::numeric >= {west}
         AND ({source} -> 'coordinates' ->> 0)::numeric <= {east}
         AND ({source} -> 'coordinates' ->> 1)::numeric >= {south}
         AND ({source} -> 'coordinates' ->> 1)::numeric <= {north}",
        bbox.maximum_longitude_span_degrees,
        bbox.maximum_latitude_span_degrees,
    )
}

fn profile_supports_command(operations: &BTreeSet<Operation>, command: PolicyCommand) -> bool {
    match command {
        PolicyCommand::Select => operations.iter().any(|operation| {
            matches!(
                operation,
                Operation::Get
                    | Operation::Lookup
                    | Operation::List
                    | Operation::Batch
                    | Operation::Revisions
                    | Operation::Snapshot
            )
        }),
        PolicyCommand::Insert => operations.contains(&Operation::Create),
        PolicyCommand::Update => operations
            .iter()
            .any(|operation| matches!(operation, Operation::Patch | Operation::Tombstone)),
    }
}

fn path_select_entities(entities: &BTreeMap<String, CompiledEntity>) -> BTreeSet<String> {
    let mut selected = BTreeSet::new();
    for source in entities.values() {
        for profile in source.access_profiles.values() {
            for grant in &profile.read_paths {
                let Some(path) = source.read_paths.get(&grant.path) else {
                    continue;
                };
                selected.insert(source.id.clone());
                selected.insert(path.through.clone());
                selected.insert(path.to.clone());
            }
        }
    }
    selected
}

fn read_path_policies_for_table(
    table_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Vec<DdlPolicy> {
    let mut policies = Vec::new();
    for source in entities.values() {
        for profile in source.access_profiles.values() {
            for grant in &profile.read_paths {
                let Some(path) = source.read_paths.get(&grant.path) else {
                    continue;
                };
                if table_entity.id == source.id {
                    policies.push(read_path_source_policy(table_entity, profile, path));
                } else if table_entity.id == path.through {
                    policies.push(read_path_through_policy(
                        table_entity,
                        source,
                        profile,
                        path,
                    ));
                } else if table_entity.id == path.to {
                    let Some(through) = entities.get(&path.through) else {
                        continue;
                    };
                    policies.push(read_path_target_policy(
                        table_entity,
                        through,
                        source,
                        profile,
                        path,
                    ));
                }
            }
        }
    }
    policies
}

fn read_path_source_policy(
    source: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
    path: &crate::model::CompiledReadPath,
) -> DdlPolicy {
    let root_id = "NULLIF(current_setting('registry.read_path_root_id', true), '')::uuid";
    DdlPolicy {
        name: read_path_policy_name(&source.id, &source.id, &profile.id, &path.id, "source"),
        command: PolicyCommand::Select,
        access_profile: profile.id.clone(),
        applies_to: DdlPolicyRole::Public,
        using_expression: Some(format!(
            "({}) AND {} AND record_id = {root_id} AND record_lifecycle = 'active'",
            policy_authority_expression(source, profile),
            read_path_setting_expression(path),
        )),
        check_expression: None,
    }
}

fn read_path_through_policy(
    through: &CompiledEntity,
    source: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
    path: &crate::model::CompiledReadPath,
) -> DdlPolicy {
    let source_ref = field_name(through, &path.source_ref);
    let root_id = "NULLIF(current_setting('registry.read_path_root_id', true), '')::uuid";
    let source_authority =
        policy_authority_expression_for_alias(source, profile, Some("path_source"));
    DdlPolicy {
        name: read_path_policy_name(&through.id, &source.id, &profile.id, &path.id, "through"),
        command: PolicyCommand::Select,
        access_profile: profile.id.clone(),
        applies_to: DdlPolicyRole::Public,
        using_expression: Some(format!(
            "({}) AND {} AND record_lifecycle = 'active' AND {source_ref} = {root_id}
             AND EXISTS (
                 SELECT 1
                   FROM registry_data.{} AS path_source
                  WHERE path_source.record_id = {source_ref}
                    AND path_source.record_lifecycle = 'active'
                    AND ({source_authority})
             )",
            session_authority_expression(profile),
            read_path_setting_expression(path),
            quote_identifier(&source.physical_table),
        )),
        check_expression: None,
    }
}

fn read_path_target_policy(
    target: &CompiledEntity,
    through: &CompiledEntity,
    source: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
    path: &crate::model::CompiledReadPath,
) -> DdlPolicy {
    let through_source_ref = format!("path_edge.{}", field_name(through, &path.source_ref));
    let through_target_ref = format!("path_edge.{}", field_name(through, &path.target_ref));
    let target_table = quote_identifier(&target.physical_table);
    let target_record_id =
        field_name_with_alias(target, &target.canonical_id.id, Some(target_table.as_str()));
    let root_id = "NULLIF(current_setting('registry.read_path_root_id', true), '')::uuid";
    let source_authority =
        policy_authority_expression_for_alias(source, profile, Some("path_source"));
    DdlPolicy {
        name: read_path_policy_name(&target.id, &source.id, &profile.id, &path.id, "target"),
        command: PolicyCommand::Select,
        access_profile: profile.id.clone(),
        applies_to: DdlPolicyRole::Public,
        using_expression: Some(format!(
            "({}) AND {} AND record_lifecycle = 'active'
             AND EXISTS (
                 SELECT 1
                   FROM registry_data.{} AS path_edge
                   JOIN registry_data.{} AS path_source
                     ON path_source.record_id = {through_source_ref}
                  WHERE {through_target_ref} = {target_record_id}
                    AND {through_source_ref} = {root_id}
                    AND path_edge.record_lifecycle = 'active'
                    AND path_source.record_lifecycle = 'active'
                    AND ({source_authority})
             )",
            session_authority_expression(profile),
            read_path_setting_expression(path),
            quote_identifier(&through.physical_table),
            quote_identifier(&source.physical_table),
        )),
        check_expression: None,
    }
}

fn read_path_setting_expression(path: &crate::model::CompiledReadPath) -> String {
    format!(
        "NULLIF(current_setting('registry.read_path_id', true), '') = {}",
        quote_literal(&path.id)
    )
}

fn change_request_action_policies_for_table(entity: &CompiledEntity) -> Vec<DdlPolicy> {
    let Some(request) = &entity.change_request else {
        return Vec::new();
    };
    let mut policies = Vec::new();
    for profile in entity.access_profiles.values() {
        for operation in [
            Operation::SubmitRequest,
            Operation::ApproveRequest,
            Operation::RejectRequest,
            Operation::RequestRevision,
            Operation::ReviseRequest,
            Operation::CancelRequest,
            Operation::ApplyRequest,
        ] {
            if !profile.operations.contains(&operation) {
                continue;
            }
            let stages = if matches!(
                operation,
                Operation::ApproveRequest | Operation::RejectRequest | Operation::RequestRevision
            ) {
                request
                    .stages
                    .iter()
                    .map(|stage| Some(stage.id.as_str()))
                    .collect::<Vec<_>>()
            } else {
                vec![None]
            };
            for stage in stages {
                let select_expression = change_request_action_expression(
                    entity,
                    profile,
                    request,
                    operation,
                    stage,
                    PolicyCommand::Select,
                );
                let update_expression = change_request_action_expression(
                    entity,
                    profile,
                    request,
                    operation,
                    stage,
                    PolicyCommand::Update,
                );
                let stage_name = stage.unwrap_or("none");
                policies.push(DdlPolicy {
                    name: change_request_action_policy_name(
                        &entity.id,
                        &profile.id,
                        operation,
                        stage_name,
                        PolicyCommand::Select,
                    ),
                    command: PolicyCommand::Select,
                    access_profile: profile.id.clone(),
                    applies_to: ordinary_policy_role(entity),
                    using_expression: Some(format!(
                        "{select_expression} AND record_lifecycle = 'active'"
                    )),
                    check_expression: None,
                });
                policies.push(DdlPolicy {
                    name: change_request_action_policy_name(
                        &entity.id,
                        &profile.id,
                        operation,
                        stage_name,
                        PolicyCommand::Update,
                    ),
                    command: PolicyCommand::Update,
                    access_profile: profile.id.clone(),
                    applies_to: ordinary_policy_role(entity),
                    using_expression: Some(format!(
                        "{update_expression} AND record_lifecycle = 'active'"
                    )),
                    check_expression: Some(format!(
                        "{update_expression} AND record_lifecycle = 'active'"
                    )),
                });
            }
        }
    }
    policies
}

fn change_request_action_expression(
    entity: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
    request: &crate::model::CompiledChangeRequest,
    operation: Operation,
    stage: Option<&str>,
    command: PolicyCommand,
) -> String {
    let context = change_request_action_context_expression();
    let stage_predicate = match stage {
        Some(stage) => format!("{context} ->> 'stage' = {}", quote_literal(stage)),
        None => format!("({context} ->> 'stage') IS NULL"),
    };
    let route_id = change_request_action_route_id(&entity.id, operation, stage);
    [
        format!("jsonb_typeof({context}) = 'object'"),
        format!("{context} ->> 'version' = '1'"),
        format!(
            "{context} ->> 'requestEntityId' = {}",
            quote_literal(&entity.id)
        ),
        format!(
            "{context} ->> 'requestId' = {}::text",
            field_name(entity, "id")
        ),
        format!(
            "{context} ->> 'contractFingerprint' = {}",
            quote_literal(&request.contract_fingerprint)
        ),
        format!("({context} ->> 'actorReference') IS NOT NULL"),
        format!(
            "{context} ->> 'selectedAccessProfile' = {}",
            quote_literal(&profile.id)
        ),
        format!(
            "({context} ->> 'selectedAccessProfile') = NULLIF(current_setting('registry.access_profile', true), '')"
        ),
        format!(
            "(({context} ->> 'principal') IS NULL OR ({context} ->> 'principal') = NULLIF(current_setting('registry.principal', true), ''))"
        ),
        format!(
            "(({context} ->> 'purpose') IS NULL OR ({context} ->> 'purpose') = NULLIF(current_setting('registry.purpose', true), ''))"
        ),
        format!(
            "{context} ->> 'operation' = {}",
            quote_literal(change_request_operation_name(operation))
        ),
        stage_predicate,
        format!("{context} ->> 'routeId' = {}", quote_literal(&route_id)),
        format!(
            "{context} ->> 'activePackageRevision' = NULLIF(current_setting('registry.active_package_revision', true), '')"
        ),
        policy_authority_expression(entity, profile),
        change_request_action_state_exists_expression(operation, command),
    ]
    .join(" AND ")
}

fn change_request_action_state_exists_expression(
    operation: Operation,
    command: PolicyCommand,
) -> String {
    let context = change_request_action_context_expression();
    if command == PolicyCommand::Select {
        let mut visible_states = vec![
            "draft",
            "submitted",
            "approved",
            "needs_changes",
            "rejected",
            "canceled",
        ];
        if operation == Operation::ApplyRequest {
            visible_states.push("applied");
        }
        let visible_states = visible_states
            .into_iter()
            .map(quote_literal)
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "EXISTS (
                SELECT 1
                  FROM registry_internal.registry_request_state AS cr_state
                 WHERE cr_state.request_entity_id = ({context} ->> 'requestEntityId')
                   AND cr_state.request_id = ({context} ->> 'requestId')::uuid
                   AND cr_state.proposal_version = ({context} ->> 'proposalVersion')::bigint
                   AND cr_state.state IN ({visible_states})
            )"
        );
    }
    let states = match command {
        PolicyCommand::Update => match operation {
            Operation::SubmitRequest => vec!["draft"],
            Operation::ApproveRequest | Operation::RejectRequest | Operation::RequestRevision => {
                vec!["submitted"]
            }
            Operation::ReviseRequest => vec!["submitted", "approved", "needs_changes", "rejected"],
            Operation::CancelRequest => vec![
                "draft",
                "submitted",
                "approved",
                "needs_changes",
                "rejected",
            ],
            Operation::ApplyRequest => vec!["approved"],
            _ => Vec::new(),
        },
        PolicyCommand::Insert | PolicyCommand::Select => Vec::new(),
    }
    .into_iter()
    .map(quote_literal)
    .collect::<Vec<_>>()
    .join(", ");
    format!(
        "EXISTS (
            SELECT 1
              FROM registry_internal.registry_request_state AS cr_state
             WHERE cr_state.request_entity_id = ({context} ->> 'requestEntityId')
               AND cr_state.request_id = ({context} ->> 'requestId')::uuid
               AND cr_state.proposal_version = ({context} ->> 'proposalVersion')::bigint
               AND cr_state.state IN ({states})
        )"
    )
}

fn change_request_action_context_expression() -> &'static str {
    "NULLIF(current_setting('registry.change_request_action_context', true), '')::jsonb"
}

fn change_request_action_route_id(
    entity_id: &str,
    operation: Operation,
    stage: Option<&str>,
) -> String {
    let action_id = match operation {
        Operation::SubmitRequest => "submit",
        Operation::ApproveRequest => "approve",
        Operation::RejectRequest => "reject",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise",
        Operation::CancelRequest => "cancel",
        Operation::ApplyRequest => "apply",
        _ => "unsupported",
    };
    match stage {
        Some(stage) => format!("records.{entity_id}.request.stages.{stage}.{action_id}"),
        None => format!("records.{entity_id}.request.{action_id}"),
    }
}

fn change_request_presence_policies_for_table(
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Vec<DdlPolicy> {
    let Some(request) = &request_entity.change_request else {
        return Vec::new();
    };
    let mut policies = Vec::new();
    for grant in &request.presence_grants {
        let Some(target_entity) = entities.get(&grant.target_entity_id) else {
            continue;
        };
        let Some(target_profile) = target_entity.access_profiles.get(&grant.profile_id) else {
            continue;
        };
        policies.push(DdlPolicy {
            name: change_request_presence_policy_name(
                &request_entity.id,
                &grant.target_entity_id,
                &grant.profile_id,
                PolicyCommand::Select,
            ),
            command: PolicyCommand::Select,
            access_profile: grant.profile_id.clone(),
            applies_to: ordinary_policy_role(request_entity),
            using_expression: Some(format!(
                "{} AND record_lifecycle = 'active'",
                change_request_presence_expression(request_entity, target_profile, request, grant)
            )),
            check_expression: None,
        });
    }
    policies
}

fn change_request_presence_expression(
    request_entity: &CompiledEntity,
    target_profile: &crate::contract::AccessProfileSource,
    request: &crate::model::CompiledChangeRequest,
    grant: &crate::model::CompiledChangeRequestPresenceGrant,
) -> String {
    let context = change_request_presence_context_expression();
    [
        format!("jsonb_typeof({context}) = 'object'"),
        format!("{context} ->> 'version' = '1'"),
        format!(
            "{context} ->> 'requestEntityId' = {}",
            quote_literal(&request_entity.id)
        ),
        format!(
            "{context} ->> 'targetEntityId' = {}",
            quote_literal(&grant.target_entity_id)
        ),
        format!("({context} ->> 'targetRecordId') IS NOT NULL"),
        format!(
            "{context} ->> 'contractFingerprint' = {}",
            quote_literal(&request.contract_fingerprint)
        ),
        format!(
            "{context} ->> 'selectedAccessProfile' = {}",
            quote_literal(&grant.profile_id)
        ),
        format!(
            "({context} ->> 'selectedAccessProfile') = NULLIF(current_setting('registry.access_profile', true), '')"
        ),
        format!(
            "(({context} ->> 'principal') IS NULL OR ({context} ->> 'principal') = NULLIF(current_setting('registry.principal', true), ''))"
        ),
        format!(
            "(({context} ->> 'purpose') IS NULL OR ({context} ->> 'purpose') = NULLIF(current_setting('registry.purpose', true), ''))"
        ),
        format!(
            "{context} ->> 'activePackageRevision' = NULLIF(current_setting('registry.active_package_revision', true), '')"
        ),
        session_authority_expression(target_profile),
        change_request_presence_boundary_expression(request_entity, &grant.request_row_boundaries),
        change_request_presence_target_exists_expression(request_entity),
    ]
    .join(" AND ")
}

fn change_request_presence_target_exists_expression(request_entity: &CompiledEntity) -> String {
    let context = change_request_presence_context_expression();
    format!(
        "EXISTS (
            SELECT 1
              FROM registry_internal.registry_request_state AS cr_state
              JOIN registry_internal.registry_request_proposals AS cr_proposal
                ON cr_proposal.request_entity_id = cr_state.request_entity_id
               AND cr_proposal.request_id = cr_state.request_id
               AND cr_proposal.proposal_version = cr_state.proposal_version
              JOIN registry_internal.registry_request_targets AS cr_target
                ON cr_target.request_entity_id = cr_proposal.request_entity_id
               AND cr_target.request_id = cr_proposal.request_id
               AND cr_target.proposal_version = cr_proposal.proposal_version
             WHERE cr_state.request_entity_id = ({context} ->> 'requestEntityId')
               AND cr_state.request_id = {request_id}
               AND cr_state.state IN ('submitted', 'approved')
               AND cr_proposal.contract_fingerprint = ({context} ->> 'contractFingerprint')
               AND cr_target.target_entity_id = ({context} ->> 'targetEntityId')
               AND cr_target.target_record_id = ({context} ->> 'targetRecordId')::uuid
        )",
        request_id = field_name(request_entity, "id"),
    )
}

fn change_request_presence_boundary_expression(
    entity: &CompiledEntity,
    boundaries: &[crate::contract::RowBoundarySource],
) -> String {
    let context = format!(
        "({} -> 'requestRowBoundaries')",
        change_request_presence_context_expression()
    );
    let mut predicates = vec![
        format!("jsonb_typeof({context}) = 'array'"),
        format!("jsonb_array_length({context}) = {}", boundaries.len()),
    ];
    for (index, boundary) in boundaries.iter().enumerate() {
        let entry = format!("({context} -> {index})");
        let values = format!("({entry} -> 'values')");
        predicates.push(format!("jsonb_typeof({entry}) = 'object'"));
        predicates.push(format!(
            "({entry} - 'field' - 'operator' - 'values') = '{{}}'::jsonb"
        ));
        predicates.push(format!(
            "{entry} ->> 'field' = {}",
            quote_literal(&boundary.field)
        ));
        predicates.push(format!(
            "{entry} ->> 'operator' = {}",
            quote_literal(match boundary.operator {
                BoundaryOperator::Equals => "equals",
                BoundaryOperator::In => "in",
            })
        ));
        predicates.push(format!("jsonb_typeof({values}) = 'array'"));
        let column = field_name(entity, &boundary.field);
        let value_type = policy_value_type(&logical_field_type(entity, &boundary.field));
        match boundary.operator {
            BoundaryOperator::Equals => {
                predicates.push(format!("jsonb_array_length({values}) = 1"));
                predicates.push(format!("{column} = ({values} ->> 0)::{value_type}"));
            }
            BoundaryOperator::In => {
                predicates.push(format!("jsonb_array_length({values}) BETWEEN 1 AND 64"));
                predicates.push(format!(
                    "{column} = ANY (ARRAY(SELECT boundary_value::{value_type} FROM jsonb_array_elements_text({values}) AS boundary_values(boundary_value)))"
                ));
            }
        }
    }
    predicates.join(" AND ")
}

fn change_request_presence_context_expression() -> &'static str {
    "NULLIF(current_setting('registry.change_request_presence_context', true), '')::jsonb"
}

fn change_request_target_policies_for_table(
    target_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Vec<DdlPolicy> {
    let mut policies = Vec::new();
    for request_entity in entities.values() {
        let Some(request) = &request_entity.change_request else {
            continue;
        };
        for effect in request
            .effects
            .iter()
            .filter(|effect| effect.target.entity_id == target_entity.id)
        {
            for profile in request_entity.access_profiles.values() {
                if profile.operations.iter().any(|operation| {
                    matches!(
                        operation,
                        Operation::SubmitRequest | Operation::ReviseRequest
                    )
                }) {
                    policies.push(DdlPolicy {
                        name: change_request_policy_name(
                            &request_entity.id,
                            &target_entity.id,
                            &profile.id,
                            &effect.id,
                            "prepare",
                            PolicyCommand::Select,
                        ),
                        command: PolicyCommand::Select,
                        access_profile: profile.id.clone(),
                        applies_to: ordinary_policy_role(target_entity),
                        using_expression: Some(format!(
                            "{} AND record_lifecycle = 'active'",
                            change_request_preparation_expression(
                                target_entity,
                                profile,
                                request,
                                effect,
                            )
                        )),
                        check_expression: None,
                    });
                }
            }
            for grant in request
                .review_grants
                .iter()
                .filter(|grant| grant.target_entity_id == target_entity.id)
            {
                if !effect_fields(effect).is_subset(&grant.readable_fields) {
                    continue;
                }
                policies.push(DdlPolicy {
                    name: change_request_policy_name(
                        &request_entity.id,
                        &target_entity.id,
                        &grant.profile_id,
                        &effect.id,
                        &format!("review-{}", grant.stage),
                        PolicyCommand::Select,
                    ),
                    command: PolicyCommand::Select,
                    access_profile: grant.profile_id.clone(),
                    applies_to: ordinary_policy_role(target_entity),
                    using_expression: Some(format!(
                        "{} AND record_lifecycle = 'active'",
                        change_request_review_expression(
                            target_entity,
                            request_entity,
                            request,
                            effect,
                            grant,
                        )
                    )),
                    check_expression: None,
                });
            }
            for grant in request
                .apply_grants
                .iter()
                .filter(|grant| grant.target_entity_id == target_entity.id)
            {
                let expression = change_request_application_expression(
                    target_entity,
                    request_entity,
                    request,
                    effect,
                    grant,
                );
                match effect.operation {
                    Operation::Create => {
                        let bounded_return_row =
                            format!("{expression} AND record_lifecycle = 'active'");
                        policies.push(DdlPolicy {
                            name: change_request_policy_name(
                                &request_entity.id,
                                &target_entity.id,
                                &grant.profile_id,
                                &effect.id,
                                "apply",
                                PolicyCommand::Select,
                            ),
                            command: PolicyCommand::Select,
                            access_profile: grant.profile_id.clone(),
                            applies_to: ordinary_policy_role(target_entity),
                            using_expression: Some(bounded_return_row.clone()),
                            check_expression: None,
                        });
                        policies.push(DdlPolicy {
                            name: change_request_policy_name(
                                &request_entity.id,
                                &target_entity.id,
                                &grant.profile_id,
                                &effect.id,
                                "apply",
                                PolicyCommand::Insert,
                            ),
                            command: PolicyCommand::Insert,
                            access_profile: grant.profile_id.clone(),
                            applies_to: ordinary_policy_role(target_entity),
                            using_expression: None,
                            check_expression: Some(bounded_return_row),
                        });
                    }
                    Operation::Patch => {
                        let bounded_return_row =
                            format!("{expression} AND record_lifecycle = 'active'");
                        let bounded_current_row = format!(
                            "{bounded_return_row} AND record_revision = ({} ->> 'expectedRevision')::bigint",
                            change_request_context_expression()
                        );
                        policies.push(DdlPolicy {
                            name: change_request_policy_name(
                                &request_entity.id,
                                &target_entity.id,
                                &grant.profile_id,
                                &effect.id,
                                "apply",
                                PolicyCommand::Select,
                            ),
                            command: PolicyCommand::Select,
                            access_profile: grant.profile_id.clone(),
                            applies_to: ordinary_policy_role(target_entity),
                            using_expression: Some(bounded_return_row.clone()),
                            check_expression: None,
                        });
                        policies.push(DdlPolicy {
                            name: change_request_policy_name(
                                &request_entity.id,
                                &target_entity.id,
                                &grant.profile_id,
                                &effect.id,
                                "apply",
                                PolicyCommand::Update,
                            ),
                            command: PolicyCommand::Update,
                            access_profile: grant.profile_id.clone(),
                            applies_to: ordinary_policy_role(target_entity),
                            using_expression: Some(bounded_current_row),
                            check_expression: Some(bounded_return_row),
                        });
                    }
                    _ => {}
                }
            }
        }
    }
    policies
}

fn change_request_preparation_expression(
    target_entity: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
    request: &crate::model::CompiledChangeRequest,
    effect: &CompiledChangeRequestEffect,
) -> String {
    let context = change_request_context_expression();
    let request_state_exists = format!(
        "EXISTS (
            SELECT 1
              FROM registry_internal.registry_request_state AS cr_state
             WHERE cr_state.request_entity_id = ({context} ->> 'requestEntityId')
               AND cr_state.request_id = ({context} ->> 'requestId')::uuid
               AND cr_state.proposal_version = ({context} ->> 'proposalVersion')::bigint
               AND cr_state.state = 'draft'
               AND cr_state.owner_reference = ({context} ->> 'actorReference')
        )"
    );
    [
        change_request_common_expression(
            target_entity,
            &profile.id,
            request,
            effect,
            "preparation",
            None,
        ),
        session_authority_expression(profile),
        format!("{context} -> 'targetRowBoundaries' = '[]'::jsonb"),
        request_state_exists,
    ]
    .join(" AND ")
}

fn change_request_review_expression(
    target_entity: &CompiledEntity,
    request_entity: &CompiledEntity,
    request: &crate::model::CompiledChangeRequest,
    effect: &CompiledChangeRequestEffect,
    grant: &crate::model::CompiledChangeRequestReviewGrant,
) -> String {
    [
        change_request_common_expression(
            target_entity,
            &grant.profile_id,
            request,
            effect,
            "review",
            Some(&grant.stage),
        ),
        session_authority_expression(&request_entity.access_profiles[&grant.profile_id]),
        change_request_proposal_target_exists_expression("submitted", effect),
        change_request_target_boundary_expression(target_entity, &grant.row_boundaries),
    ]
    .join(" AND ")
}

fn change_request_application_expression(
    target_entity: &CompiledEntity,
    request_entity: &CompiledEntity,
    request: &crate::model::CompiledChangeRequest,
    effect: &CompiledChangeRequestEffect,
    grant: &crate::model::CompiledChangeRequestApplyGrant,
) -> String {
    [
        change_request_common_expression(
            target_entity,
            &grant.profile_id,
            request,
            effect,
            "application",
            None,
        ),
        session_authority_expression(&request_entity.access_profiles[&grant.profile_id]),
        change_request_proposal_target_exists_expression("approved", effect),
        change_request_target_boundary_expression(target_entity, &grant.row_boundaries),
    ]
    .join(" AND ")
}

fn change_request_common_expression(
    target_entity: &CompiledEntity,
    profile_id: &str,
    request: &crate::model::CompiledChangeRequest,
    effect: &CompiledChangeRequestEffect,
    phase: &str,
    stage: Option<&str>,
) -> String {
    let context = change_request_context_expression();
    let field_plan = serde_json::to_string(&effect_fields(effect).into_iter().collect::<Vec<_>>())
        .expect("compiled field plan serializes");
    let phase_value = match stage {
        Some(stage) => serde_json::json!({"kind": phase, "stage": stage}),
        None => serde_json::json!({"kind": phase}),
    };
    let phase_plan = serde_json::to_string(&phase_value).expect("compiled phase serializes");
    let mut predicates = vec![
        format!("jsonb_typeof({context}) = 'object'"),
        format!("{context} ->> 'version' = '1'"),
        format!(
            "{context} ->> 'requestEntityId' = {}",
            quote_literal(&request.request_entity_id)
        ),
        format!(
            "{context} ->> 'contractFingerprint' = {}",
            quote_literal(&request.contract_fingerprint)
        ),
        format!("({context} ->> 'effectDigest') ~ '^sha256:[0-9a-f]{{64}}$'"),
        format!("({context} ->> 'actorReference') IS NOT NULL"),
        format!(
            "{context} ->> 'selectedAccessProfile' = {}",
            quote_literal(profile_id)
        ),
        format!(
            "({context} ->> 'selectedAccessProfile') = NULLIF(current_setting('registry.access_profile', true), '')"
        ),
        format!(
            "(({context} ->> 'principal') IS NULL OR ({context} ->> 'principal') = NULLIF(current_setting('registry.principal', true), ''))"
        ),
        format!(
            "(({context} ->> 'purpose') IS NULL OR ({context} ->> 'purpose') = NULLIF(current_setting('registry.purpose', true), ''))"
        ),
        format!(
            "{context} ->> 'effectId' = {}",
            quote_literal(&effect.id)
        ),
        format!(
            "{context} ->> 'targetEntityId' = {}",
            quote_literal(&effect.target.entity_id)
        ),
        format!(
            "{context} ->> 'operation' = {}",
            quote_literal(operation_name(effect.operation))
        ),
        format!("{context} -> 'fields' = {}::jsonb", quote_literal(&field_plan)),
        format!(
            "{context} ->> 'activePackageRevision' = NULLIF(current_setting('registry.active_package_revision', true), '')"
        ),
        format!(
            "{context} ->> 'targetRecordId' = {}::text",
            field_name(target_entity, "id")
        ),
    ];
    predicates.push(format!(
        "{context} -> 'phase' = {}::jsonb",
        quote_literal(&phase_plan)
    ));
    predicates.join(" AND ")
}

fn change_request_proposal_target_exists_expression(
    required_state: &str,
    effect: &CompiledChangeRequestEffect,
) -> String {
    let context = change_request_context_expression();
    let expected_revision = match effect.operation {
        Operation::Create => format!("({context} ->> 'expectedRevision') IS NULL"),
        Operation::Patch => format!("({context} ->> 'expectedRevision') IS NOT NULL"),
        _ => "false".to_owned(),
    };
    format!(
        "{expected_revision}
         AND EXISTS (
             SELECT 1
               FROM registry_internal.registry_request_state AS cr_state
               JOIN registry_internal.registry_request_proposals AS cr_proposal
                 ON cr_proposal.request_entity_id = cr_state.request_entity_id
                AND cr_proposal.request_id = cr_state.request_id
                AND cr_proposal.proposal_version = cr_state.proposal_version
               JOIN registry_internal.registry_request_targets AS cr_target
                 ON cr_target.request_entity_id = cr_proposal.request_entity_id
                AND cr_target.request_id = cr_proposal.request_id
                AND cr_target.proposal_version = cr_proposal.proposal_version
              WHERE cr_state.request_entity_id = ({context} ->> 'requestEntityId')
                AND cr_state.request_id = ({context} ->> 'requestId')::uuid
                AND cr_state.proposal_version = ({context} ->> 'proposalVersion')::bigint
                AND cr_state.state = {state}
                AND cr_proposal.contract_fingerprint = ({context} ->> 'contractFingerprint')
                AND cr_proposal.effect_digest = ({context} ->> 'effectDigest')
                AND cr_target.target_entity_id = ({context} ->> 'targetEntityId')
                AND cr_target.target_record_id = ({context} ->> 'targetRecordId')::uuid
                AND cr_target.operation = ({context} ->> 'operation')
                AND (
                    (cr_target.expected_revision IS NULL AND ({context} ->> 'expectedRevision') IS NULL)
                    OR cr_target.expected_revision = ({context} ->> 'expectedRevision')::bigint
                )
         )",
        state = quote_literal(required_state),
    )
}

fn change_request_target_boundary_expression(
    entity: &CompiledEntity,
    boundaries: &[crate::contract::RowBoundarySource],
) -> String {
    let context = format!(
        "({} -> 'targetRowBoundaries')",
        change_request_context_expression()
    );
    let mut predicates = vec![
        format!("jsonb_typeof({context}) = 'array'"),
        format!("jsonb_array_length({context}) = {}", boundaries.len()),
    ];
    for (index, boundary) in boundaries.iter().enumerate() {
        let entry = format!("({context} -> {index})");
        let values = format!("({entry} -> 'values')");
        predicates.push(format!("jsonb_typeof({entry}) = 'object'"));
        predicates.push(format!(
            "({entry} - 'field' - 'operator' - 'values') = '{{}}'::jsonb"
        ));
        predicates.push(format!(
            "{entry} ->> 'field' = {}",
            quote_literal(&boundary.field)
        ));
        predicates.push(format!(
            "{entry} ->> 'operator' = {}",
            quote_literal(match boundary.operator {
                BoundaryOperator::Equals => "equals",
                BoundaryOperator::In => "in",
            })
        ));
        predicates.push(format!("jsonb_typeof({values}) = 'array'"));
        let column = field_name(entity, &boundary.field);
        let value_type = policy_value_type(&logical_field_type(entity, &boundary.field));
        match boundary.operator {
            BoundaryOperator::Equals => {
                predicates.push(format!("jsonb_array_length({values}) = 1"));
                predicates.push(format!("{column} = ({values} ->> 0)::{value_type}"));
            }
            BoundaryOperator::In => {
                predicates.push(format!("jsonb_array_length({values}) BETWEEN 1 AND 64"));
                predicates.push(format!(
                    "{column} = ANY (ARRAY(SELECT boundary_value::{value_type} FROM jsonb_array_elements_text({values}) AS boundary_values(boundary_value)))"
                ));
            }
        }
    }
    predicates.join(" AND ")
}

fn immediate_action_target_policies_for_table(
    target_entity: &CompiledEntity,
    actions: &CompiledActionInventory,
) -> Vec<DdlPolicy> {
    let mut policies = Vec::new();
    for action in &actions.actions {
        for effect in action
            .effects
            .iter()
            .filter(|effect| effect.target.entity_id == target_entity.id)
        {
            for grant in action.grants.iter().filter(|grant| {
                grant.operations.contains(&Operation::Invoke)
                    && grant
                        .targets
                        .iter()
                        .any(|target| target.entity_id == target_entity.id)
            }) {
                let expression = immediate_action_application_expression(
                    target_entity,
                    action,
                    effect,
                    &grant.profile_id,
                );
                let bounded_return_row = format!("{expression} AND record_lifecycle = 'active'");
                let write_context = immediate_action_write_context_expression(
                    immediate_action_context_expression(),
                );
                let lock_context =
                    immediate_action_lock_context_expression(immediate_action_context_expression());
                policies.push(DdlPolicy {
                    name: immediate_action_policy_name(
                        &action.id,
                        &target_entity.id,
                        &grant.profile_id,
                        &effect.id,
                        PolicyCommand::Select,
                    ),
                    command: PolicyCommand::Select,
                    access_profile: grant.profile_id.clone(),
                    applies_to: ordinary_policy_role(target_entity),
                    using_expression: Some(bounded_return_row.clone()),
                    check_expression: None,
                });
                match effect.operation {
                    Operation::Create => {
                        policies.push(DdlPolicy {
                            name: immediate_action_policy_name(
                                &action.id,
                                &target_entity.id,
                                &grant.profile_id,
                                &effect.id,
                                PolicyCommand::Insert,
                            ),
                            command: PolicyCommand::Insert,
                            access_profile: grant.profile_id.clone(),
                            applies_to: ordinary_policy_role(target_entity),
                            using_expression: None,
                            check_expression: Some(format!(
                                "{bounded_return_row} AND {write_context}"
                            )),
                        });
                    }
                    Operation::Patch => {
                        let bounded_current_row = format!(
                            "{bounded_return_row} AND {write_context} AND record_revision = ({} ->> 'expectedRevision')::bigint",
                            immediate_action_context_expression()
                        );
                        policies.push(DdlPolicy {
                            name: immediate_action_policy_name(
                                &action.id,
                                &target_entity.id,
                                &grant.profile_id,
                                &effect.id,
                                PolicyCommand::Update,
                            ),
                            command: PolicyCommand::Update,
                            access_profile: grant.profile_id.clone(),
                            applies_to: ordinary_policy_role(target_entity),
                            using_expression: Some(bounded_current_row),
                            check_expression: Some(format!(
                                "{bounded_return_row} AND {write_context}"
                            )),
                        });
                        policies.push(DdlPolicy {
                            name: immediate_action_lock_policy_name(
                                &action.id,
                                &target_entity.id,
                                &grant.profile_id,
                                &effect.id,
                            ),
                            command: PolicyCommand::Update,
                            access_profile: grant.profile_id.clone(),
                            applies_to: ordinary_policy_role(target_entity),
                            using_expression: Some(format!(
                                "{bounded_return_row} AND {lock_context}"
                            )),
                            check_expression: Some("false".to_owned()),
                        });
                    }
                    _ => {}
                }
            }
        }

        for target_use in action.target_uses.iter().filter(|target_use| {
            target_use.entity_id == target_entity.id
                && target_use.operation == Operation::Invoke
                && target_use.fields.is_empty()
                && !target_use.condition_required
                && matches!(
                    &target_use.source,
                    CompiledActionTargetUseSource::Input { .. }
                )
        }) {
            let CompiledActionTargetUseSource::Input { input } = &target_use.source else {
                continue;
            };
            for grant in action.grants.iter().filter(|grant| {
                grant.operations.contains(&Operation::Invoke)
                    && grant
                        .targets
                        .iter()
                        .any(|target| target.entity_id == target_entity.id)
            }) {
                let expression = immediate_action_link_expression(
                    target_entity,
                    action,
                    target_use,
                    input,
                    &grant.profile_id,
                );
                policies.push(DdlPolicy {
                    name: immediate_action_link_policy_name(
                        &action.id,
                        &target_entity.id,
                        &grant.profile_id,
                        input,
                    ),
                    command: PolicyCommand::Select,
                    access_profile: grant.profile_id.clone(),
                    applies_to: ordinary_policy_role(target_entity),
                    using_expression: Some(format!("{expression} AND record_lifecycle = 'active'")),
                    check_expression: None,
                });
                policies.push(DdlPolicy {
                    name: immediate_action_link_lock_policy_name(
                        &action.id,
                        &target_entity.id,
                        &grant.profile_id,
                        input,
                    ),
                    command: PolicyCommand::Update,
                    access_profile: grant.profile_id.clone(),
                    applies_to: ordinary_policy_role(target_entity),
                    using_expression: Some(format!("{expression} AND record_lifecycle = 'active'")),
                    check_expression: Some("false".to_owned()),
                });
            }
        }
    }
    policies
}

fn immediate_action_application_expression(
    target_entity: &CompiledEntity,
    action: &CompiledAction,
    effect: &CompiledActionEffect,
    profile_id: &str,
) -> String {
    [
        immediate_action_common_expression(target_entity, action, effect, profile_id),
        immediate_action_target_boundary_expression(
            immediate_action_context_expression(),
            target_entity,
            action
                .grants
                .iter()
                .find(|grant| grant.profile_id == profile_id)
                .and_then(|grant| {
                    grant
                        .targets
                        .iter()
                        .find(|target| target.entity_id == target_entity.id)
                })
                .map(|target| target.row_boundaries.as_slice())
                .unwrap_or(&[]),
        ),
    ]
    .join(" AND ")
}

fn immediate_action_link_expression(
    target_entity: &CompiledEntity,
    action: &CompiledAction,
    target_use: &CompiledActionTargetUse,
    input_id: &str,
    profile_id: &str,
) -> String {
    [
        immediate_action_link_common_expression(
            target_entity,
            action,
            target_use,
            input_id,
            profile_id,
        ),
        immediate_action_target_boundary_expression(
            immediate_action_link_context_expression(),
            target_entity,
            action
                .grants
                .iter()
                .find(|grant| grant.profile_id == profile_id)
                .and_then(|grant| {
                    grant
                        .targets
                        .iter()
                        .find(|target| target.entity_id == target_entity.id)
                })
                .map(|target| target.row_boundaries.as_slice())
                .unwrap_or(&[]),
        ),
    ]
    .join(" AND ")
}

fn immediate_action_link_common_expression(
    target_entity: &CompiledEntity,
    action: &CompiledAction,
    target_use: &CompiledActionTargetUse,
    input_id: &str,
    profile_id: &str,
) -> String {
    let context = immediate_action_link_context_expression();
    vec![
        format!("jsonb_typeof({context}) = 'object'"),
        format!("{context} ->> 'version' = '1'"),
        format!("{context} ->> 'actionId' = {}", quote_literal(&action.id)),
        format!(
            "{context} ->> 'contractFingerprint' = {}",
            quote_literal(&action.contract_fingerprint)
        ),
        format!(
            "{context} ->> 'selectedAccessProfile' = {}",
            quote_literal(profile_id)
        ),
        format!(
            "({context} ->> 'selectedAccessProfile') = NULLIF(current_setting('registry.access_profile', true), '')"
        ),
        format!(
            "({context} ->> 'principal') = NULLIF(current_setting('registry.principal', true), '')"
        ),
        format!(
            "(({context} ->> 'purpose') IS NULL OR ({context} ->> 'purpose') = NULLIF(current_setting('registry.purpose', true), ''))"
        ),
        format!("{context} ->> 'inputId' = {}", quote_literal(input_id)),
        format!(
            "{context} ->> 'targetEntityId' = {}",
            quote_literal(&target_use.entity_id)
        ),
        format!(
            "{context} ->> 'operation' = {}",
            quote_literal(operation_name(target_use.operation))
        ),
        format!(
            "{context} ->> 'activePackageRevision' = NULLIF(current_setting('registry.active_package_revision', true), '')"
        ),
        format!(
            "{context} ->> 'targetRecordId' = {}::text",
            field_name(target_entity, "id")
        ),
    ]
    .join(" AND ")
}

fn immediate_action_common_expression(
    target_entity: &CompiledEntity,
    action: &CompiledAction,
    effect: &CompiledActionEffect,
    profile_id: &str,
) -> String {
    let context = immediate_action_context_expression();
    vec![
        format!("jsonb_typeof({context}) = 'object'"),
        format!("{context} ->> 'version' = '1'"),
        format!("{context} ->> 'actionId' = {}", quote_literal(&action.id)),
        format!(
            "{context} ->> 'contractFingerprint' = {}",
            quote_literal(&action.contract_fingerprint)
        ),
        format!(
            "{context} ->> 'selectedAccessProfile' = {}",
            quote_literal(profile_id)
        ),
        format!(
            "({context} ->> 'selectedAccessProfile') = NULLIF(current_setting('registry.access_profile', true), '')"
        ),
        format!(
            "({context} ->> 'principal') = NULLIF(current_setting('registry.principal', true), '')"
        ),
        format!(
            "(({context} ->> 'purpose') IS NULL OR ({context} ->> 'purpose') = NULLIF(current_setting('registry.purpose', true), ''))"
        ),
        immediate_action_effect_group_expression(context, action, effect),
        format!(
            "{context} ->> 'targetEntityId' = {}",
            quote_literal(&effect.target.entity_id)
        ),
        format!(
            "{context} ->> 'operation' = {}",
            quote_literal(operation_name(effect.operation))
        ),
        format!(
            "{context} ->> 'activePackageRevision' = NULLIF(current_setting('registry.active_package_revision', true), '')"
        ),
        format!(
            "{context} ->> 'targetRecordId' = {}::text",
            field_name(target_entity, "id")
        ),
    ]
    .join(" AND ")
}

fn immediate_action_effect_group_expression(
    context: &str,
    action: &CompiledAction,
    effect: &CompiledActionEffect,
) -> String {
    let compatible = action
        .effects
        .iter()
        .filter(|candidate| action_effects_can_share_target(effect, candidate))
        .collect::<Vec<_>>();
    let allowed_effects = compatible
        .iter()
        .map(|candidate| quote_literal(&candidate.id))
        .collect::<Vec<_>>()
        .join(", ");
    let field_rows = compatible
        .iter()
        .flat_map(|candidate| {
            candidate.mutations.iter().map(|mutation| {
                let field = match mutation {
                    CompiledActionMutation::Set { field, .. }
                    | CompiledActionMutation::Clear { field } => field,
                };
                format!(
                    "({}, {})",
                    quote_literal(&candidate.id),
                    quote_literal(field)
                )
            })
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "jsonb_typeof({context} -> 'effectIds') = 'array' \
         AND jsonb_array_length({context} -> 'effectIds') BETWEEN 1 AND 128 \
         AND jsonb_array_length({context} -> 'effectIds') = ( \
             SELECT count(DISTINCT context_effects.effect_id) \
               FROM jsonb_array_elements_text({context} -> 'effectIds') AS context_effects(effect_id) \
         ) \
         AND jsonb_typeof({context} -> 'fields') = 'array' \
         AND ({context} -> 'effectIds') ? {effect_id} \
         AND NOT EXISTS ( \
             SELECT 1 \
               FROM jsonb_array_elements_text({context} -> 'effectIds') AS context_effects(effect_id) \
              WHERE context_effects.effect_id NOT IN ({allowed_effects}) \
         ) \
         AND {context} -> 'fields' = ( \
             SELECT COALESCE(jsonb_agg(selected_fields.field ORDER BY selected_fields.field), '[]'::jsonb) \
               FROM ( \
                   SELECT DISTINCT effect_fields.field \
                     FROM (VALUES {field_rows}) AS effect_fields(effect_id, field) \
                    WHERE EXISTS ( \
                         SELECT 1 \
                           FROM jsonb_array_elements_text({context} -> 'effectIds') AS context_effects(effect_id) \
                          WHERE context_effects.effect_id = effect_fields.effect_id \
                    ) \
               ) AS selected_fields \
         )",
        effect_id = quote_literal(&effect.id),
    )
}

fn action_effects_can_share_target(
    left: &CompiledActionEffect,
    right: &CompiledActionEffect,
) -> bool {
    if left.target.entity_id != right.target.entity_id || left.operation != right.operation {
        return false;
    }
    match (&left.target.binding, &right.target.binding) {
        (
            crate::model::CompiledActionTargetBinding::Create,
            crate::model::CompiledActionTargetBinding::Create,
        ) => left.id == right.id,
        (
            crate::model::CompiledActionTargetBinding::Existing { .. },
            crate::model::CompiledActionTargetBinding::Existing { .. },
        ) => true,
        _ => false,
    }
}

fn immediate_action_target_boundary_expression(
    context_expression: &str,
    entity: &CompiledEntity,
    boundaries: &[crate::contract::RowBoundarySource],
) -> String {
    let context = format!("({context_expression} -> 'targetRowBoundaries')");
    let mut predicates = vec![
        format!("jsonb_typeof({context}) = 'array'"),
        format!("jsonb_array_length({context}) = {}", boundaries.len()),
    ];
    for (index, boundary) in boundaries.iter().enumerate() {
        let entry = format!("({context} -> {index})");
        let values = format!("({entry} -> 'values')");
        predicates.push(format!("jsonb_typeof({entry}) = 'object'"));
        predicates.push(format!(
            "({entry} - 'field' - 'operator' - 'values') = '{{}}'::jsonb"
        ));
        predicates.push(format!(
            "{entry} ->> 'field' = {}",
            quote_literal(&boundary.field)
        ));
        predicates.push(format!(
            "{entry} ->> 'operator' = {}",
            quote_literal(match boundary.operator {
                BoundaryOperator::Equals => "equals",
                BoundaryOperator::In => "in",
            })
        ));
        predicates.push(format!("jsonb_typeof({values}) = 'array'"));
        let column = field_name(entity, &boundary.field);
        let value_type = policy_value_type(&logical_field_type(entity, &boundary.field));
        match boundary.operator {
            BoundaryOperator::Equals => {
                predicates.push(format!("jsonb_array_length({values}) = 1"));
                predicates.push(format!("{column} = ({values} ->> 0)::{value_type}"));
            }
            BoundaryOperator::In => {
                predicates.push(format!("jsonb_array_length({values}) BETWEEN 1 AND 64"));
                predicates.push(format!(
                    "{column} = ANY (ARRAY(SELECT boundary_value::{value_type} FROM jsonb_array_elements_text({values}) AS boundary_values(boundary_value)))"
                ));
            }
        }
    }
    predicates.join(" AND ")
}

fn immediate_action_context_expression() -> &'static str {
    "NULLIF(current_setting('registry.immediate_action_target_context', true), '')::jsonb"
}

fn immediate_action_link_context_expression() -> &'static str {
    "NULLIF(current_setting('registry.immediate_action_link_context', true), '')::jsonb"
}

fn immediate_action_write_context_expression(context: &str) -> String {
    format!(
        "{context} -> 'lockOnly' = 'false'::jsonb AND {}",
        immediate_action_application_id_context_expression(context)
    )
}

fn immediate_action_lock_context_expression(context: &str) -> String {
    format!(
        "{context} -> 'lockOnly' = 'true'::jsonb AND ({context} ->> 'expectedRevision') IS NULL AND {}",
        immediate_action_application_id_context_expression(context)
    )
}

fn immediate_action_application_id_context_expression(context: &str) -> String {
    format!(
        "({context} ->> 'applicationId') ~* '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$'"
    )
}

fn change_request_context_expression() -> &'static str {
    "NULLIF(current_setting('registry.change_request_target_context', true), '')::jsonb"
}

fn effect_fields(effect: &CompiledChangeRequestEffect) -> BTreeSet<String> {
    effect
        .mutations
        .iter()
        .map(|mutation| match mutation {
            CompiledChangeRequestMutation::Set { field, .. }
            | CompiledChangeRequestMutation::Clear { field } => field.clone(),
        })
        .collect()
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Patch => "patch",
        Operation::Invoke => "invoke",
        _ => "unsupported",
    }
}

fn change_request_operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::SubmitRequest => "submit_request",
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
        _ => "unsupported",
    }
}

fn change_request_policy_name(
    request_entity_id: &str,
    target_entity_id: &str,
    profile_id: &str,
    effect_id: &str,
    phase: &str,
    command: PolicyCommand,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/change-request-target-rls-policy/v1");
    for value in [
        request_entity_id,
        target_entity_id,
        profile_id,
        effect_id,
        phase,
        command.as_sql(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "registry_cr_rls_{}_{}",
        command.as_sql().to_ascii_lowercase(),
        suffix
    )
}

fn immediate_action_policy_name(
    action_id: &str,
    target_entity_id: &str,
    profile_id: &str,
    effect_id: &str,
    command: PolicyCommand,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/immediate-action-target-rls-policy/v1");
    for value in [
        action_id,
        target_entity_id,
        profile_id,
        effect_id,
        command.as_sql(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "registry_action_rls_{}_{}",
        command.as_sql().to_ascii_lowercase(),
        suffix
    )
}

fn immediate_action_lock_policy_name(
    action_id: &str,
    target_entity_id: &str,
    profile_id: &str,
    effect_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/immediate-action-target-lock-rls-policy/v1");
    for value in [action_id, target_entity_id, profile_id, effect_id] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("registry_action_rls_lock_update_{suffix}")
}

fn immediate_action_link_policy_name(
    action_id: &str,
    target_entity_id: &str,
    profile_id: &str,
    input_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/immediate-action-link-rls-policy/v1");
    for value in [action_id, target_entity_id, profile_id, input_id] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("registry_action_link_rls_select_{suffix}")
}

fn immediate_action_link_lock_policy_name(
    action_id: &str,
    target_entity_id: &str,
    profile_id: &str,
    input_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/immediate-action-link-lock-rls-policy/v1");
    for value in [action_id, target_entity_id, profile_id, input_id] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("registry_action_link_rls_lock_update_{suffix}")
}

fn change_request_presence_policy_name(
    request_entity_id: &str,
    target_entity_id: &str,
    profile_id: &str,
    command: PolicyCommand,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/change-request-presence-rls-policy/v1");
    for value in [
        request_entity_id,
        target_entity_id,
        profile_id,
        command.as_sql(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "registry_cr_presence_rls_{}_{}",
        command.as_sql().to_ascii_lowercase(),
        suffix
    )
}

fn change_request_action_policy_name(
    request_entity_id: &str,
    profile_id: &str,
    operation: Operation,
    stage: &str,
    command: PolicyCommand,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/change-request-action-rls-policy/v1");
    for value in [
        request_entity_id,
        profile_id,
        change_request_operation_name(operation),
        stage,
        command.as_sql(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "registry_cr_action_rls_{}_{}",
        command.as_sql().to_ascii_lowercase(),
        suffix
    )
}

fn policy_authority_expression(
    entity: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
) -> String {
    policy_authority_expression_for_alias(entity, profile, None)
}

fn policy_authority_expression_for_alias(
    entity: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
    alias: Option<&str>,
) -> String {
    let mut predicates = vec![format!(
        "NULLIF(current_setting('registry.access_profile', true), '') = {}",
        quote_literal(&profile.id)
    )];
    if !profile.anonymous {
        predicates
            .push("NULLIF(current_setting('registry.principal', true), '') IS NOT NULL".to_owned());
    }
    if !profile.required_purposes.is_empty() {
        let purposes = profile
            .required_purposes
            .iter()
            .map(|purpose| quote_literal(purpose))
            .collect::<Vec<_>>()
            .join(", ");
        predicates.push(format!(
            "NULLIF(current_setting('registry.purpose', true), '') IN ({purposes})"
        ));
    }

    let context = "NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb";
    predicates.push(format!("jsonb_typeof({context}) = 'array'"));
    predicates.push(format!(
        "jsonb_array_length({context}) = {}",
        profile.row_boundaries.len()
    ));
    for (index, boundary) in profile.row_boundaries.iter().enumerate() {
        let entry = format!("({context} -> {index})");
        let values = format!("({entry} -> 'values')");
        predicates.push(format!("jsonb_typeof({entry}) = 'object'"));
        predicates.push(format!(
            "({entry} - 'field' - 'operator' - 'values') = '{{}}'::jsonb"
        ));
        predicates.push(format!(
            "{entry} ->> 'field' = {}",
            quote_literal(&boundary.field)
        ));
        predicates.push(format!(
            "{entry} ->> 'operator' = {}",
            quote_literal(match boundary.operator {
                BoundaryOperator::Equals => "equals",
                BoundaryOperator::In => "in",
            })
        ));
        predicates.push(format!("jsonb_typeof({values}) = 'array'"));
        let column = field_name_with_alias(entity, &boundary.field, alias);
        let value_type = policy_value_type(&logical_field_type(entity, &boundary.field));
        match boundary.operator {
            BoundaryOperator::Equals => {
                predicates.push(format!("jsonb_array_length({values}) = 1"));
                predicates.push(format!("{column} = ({values} ->> 0)::{value_type}"));
            }
            BoundaryOperator::In => {
                predicates.push(format!("jsonb_array_length({values}) BETWEEN 1 AND 64"));
                predicates.push(format!(
                    "{column} = ANY (ARRAY(SELECT boundary_value::{value_type} FROM jsonb_array_elements_text({values}) AS boundary_values(boundary_value)))"
                ));
            }
        }
    }
    predicates.join(" AND ")
}

fn session_authority_expression(profile: &crate::contract::AccessProfileSource) -> String {
    let mut predicates = vec![format!(
        "NULLIF(current_setting('registry.access_profile', true), '') = {}",
        quote_literal(&profile.id)
    )];
    if !profile.anonymous {
        predicates
            .push("NULLIF(current_setting('registry.principal', true), '') IS NOT NULL".to_owned());
    }
    if !profile.required_purposes.is_empty() {
        let purposes = profile
            .required_purposes
            .iter()
            .map(|purpose| quote_literal(purpose))
            .collect::<Vec<_>>()
            .join(", ");
        predicates.push(format!(
            "NULLIF(current_setting('registry.purpose', true), '') IN ({purposes})"
        ));
    }
    predicates.join(" AND ")
}

fn policy_value_type(field_type: &FieldTypeSource) -> &'static str {
    match field_type {
        FieldTypeSource::Boolean => "boolean",
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::VocabularyCode { .. } => "text",
        FieldTypeSource::Int64 => "bigint",
        FieldTypeSource::Decimal { .. } => "numeric",
        FieldTypeSource::Date => "date",
        FieldTypeSource::Timestamp => "timestamptz",
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => "uuid",
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => "jsonb",
    }
}

fn policy_name(entity_id: &str, profile_id: &str, command: PolicyCommand) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/rls-policy/v1");
    hasher.update((entity_id.len() as u64).to_be_bytes());
    hasher.update(entity_id.as_bytes());
    hasher.update((profile_id.len() as u64).to_be_bytes());
    hasher.update(profile_id.as_bytes());
    hasher.update(command.as_sql().as_bytes());
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "registry_rls_{}_{}",
        command.as_sql().to_ascii_lowercase(),
        suffix
    )
}

fn create_returning_policy_name(entity_id: &str, profile_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/create-returning-rls-policy/v1");
    for value in [entity_id, profile_id] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("registry_create_returning_rls_{suffix}")
}

fn spatial_bbox_policy_name(entity_id: &str, profile_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/spatial-bbox-rls-policy/v1");
    hasher.update((entity_id.len() as u64).to_be_bytes());
    hasher.update(entity_id.as_bytes());
    hasher.update((profile_id.len() as u64).to_be_bytes());
    hasher.update(profile_id.as_bytes());
    let digest = hasher.finalize();
    format!("registry_spatial_bbox_rls_{}", hex_prefix(&digest, 12))
}

fn read_path_policy_name(
    table_entity_id: &str,
    source_entity_id: &str,
    profile_id: &str,
    path_id: &str,
    role: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/read-path-rls-policy/v1");
    for value in [table_entity_id, source_entity_id, profile_id, path_id, role] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("registry_path_rls_select_{suffix}")
}

pub(crate) fn policy_sql(table: &str, policy: &DdlPolicy, role: Option<&str>) -> String {
    let mut sql = format!(
        "CREATE POLICY {} ON registry_data.{table} FOR {}",
        quote_identifier(&policy.name),
        policy.command.as_sql()
    );
    if let Some(role) = role {
        sql.push_str(" TO ");
        sql.push_str(&quote_identifier(role));
    }
    if let Some(expression) = &policy.using_expression {
        sql.push_str(" USING (");
        sql.push_str(expression);
        sql.push(')');
    }
    if let Some(expression) = &policy.check_expression {
        sql.push_str(" WITH CHECK (");
        sql.push_str(expression);
        sql.push(')');
    }
    sql
}

fn derived_reference_name<'a>(
    names: &'a crate::physical_names::EntityPhysicalNames,
    field: &str,
) -> &'a str {
    names.constraints[&format!("reference:{field}")].as_str()
}

fn constraint_sql(
    entity: &CompiledEntity,
    names: &crate::physical_names::EntityPhysicalNames,
    constraint_id: &str,
    constraint: &ConstraintSource,
) -> String {
    let table = quote_identifier(&entity.physical_table);
    let name = quote_identifier(&names.constraints[constraint_id]);
    let check = match constraint {
        ConstraintSource::Unique {
            fields, when: None, ..
        } => {
            let fields = field_list(entity, fields);
            return format!(
                "ALTER TABLE registry_data.{table} ADD CONSTRAINT {name} UNIQUE ({fields})"
            );
        }
        ConstraintSource::Unique {
            fields,
            when: Some(when),
            ..
        } => {
            let fields = field_list(entity, fields);
            let predicate = partial_unique_predicate(entity, when);
            return format!(
                "CREATE UNIQUE INDEX {name} ON registry_data.{table} ({fields}) WHERE {predicate}"
            );
        }
        ConstraintSource::Compare {
            left,
            operator,
            right,
            ..
        } => format!(
            "{} {} {}",
            field_name(entity, left),
            comparison_operator(*operator),
            field_name(entity, right)
        ),
        ConstraintSource::IntRange {
            field,
            minimum,
            maximum,
            ..
        } => {
            let column = field_name(entity, field);
            let mut parts = Vec::new();
            if let Some(minimum) = minimum {
                parts.push(format!("{column} >= {minimum}"));
            }
            if let Some(maximum) = maximum {
                parts.push(format!("{column} <= {maximum}"));
            }
            parts.join(" AND ")
        }
        ConstraintSource::Vocabulary { field, values, .. } => {
            let values = values
                .iter()
                .map(|value| quote_literal(value))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} IN ({values})", field_name(entity, field))
        }
        ConstraintSource::TemporalNonOverlap { scope_fields, .. } => {
            let (valid_from, valid_to) = temporal_boundary_fields(entity);
            let function = match valid_from.field_type {
                FieldTypeSource::Date => "daterange",
                FieldTypeSource::Timestamp => "tstzrange",
                _ => unreachable!("valid-time field kind was validated"),
            };
            let mut elements = scope_fields
                .iter()
                .map(|field| format!("{} WITH =", field_name(entity, field)))
                .collect::<Vec<_>>();
            elements.push(format!(
                "{function}({}, {}, '[)') WITH &&",
                quote_identifier(&valid_from.physical_name),
                quote_identifier(&valid_to.physical_name)
            ));
            return format!(
                "ALTER TABLE registry_data.{table} ADD CONSTRAINT {name} EXCLUDE USING gist ({}) DEFERRABLE INITIALLY IMMEDIATE",
                elements.join(", ")
            );
        }
    };
    format!("ALTER TABLE registry_data.{table} ADD CONSTRAINT {name} CHECK ({check})")
}

fn temporal_order_constraint_sql(entity: &CompiledEntity) -> String {
    let table = quote_identifier(&entity.physical_table);
    let name = quote_identifier(&temporal_order_constraint_name(&entity.id));
    let (valid_from, valid_to) = temporal_boundary_fields(entity);
    format!(
        "ALTER TABLE registry_data.{table} ADD CONSTRAINT {name} CHECK ({} IS NULL OR {} < {})",
        quote_identifier(&valid_to.physical_name),
        quote_identifier(&valid_from.physical_name),
        quote_identifier(&valid_to.physical_name)
    )
}

fn temporal_order_constraint_name(entity_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-server/temporal-order/v1");
    hasher.update((entity_id.len() as u64).to_be_bytes());
    hasher.update(entity_id.as_bytes());
    let digest = hasher.finalize();
    format!("registry_temporal_order_{}", hex_prefix(&digest, 12))
}

fn temporal_boundary_fields(
    entity: &CompiledEntity,
) -> (&crate::model::CompiledField, &crate::model::CompiledField) {
    let valid_from = entity
        .fields
        .values()
        .find(|field| field.valid_time_role == Some(ValidTimeRole::ValidFrom))
        .expect("validated valid_from field");
    let valid_to = entity
        .fields
        .values()
        .find(|field| field.valid_time_role == Some(ValidTimeRole::ValidTo))
        .expect("validated valid_to field");
    (valid_from, valid_to)
}

fn partial_unique_predicate(entity: &CompiledEntity, when: &[UniqueWhenPredicate]) -> String {
    let mut predicates = when.iter().collect::<Vec<_>>();
    predicates.sort_by_key(|predicate| unique_when_predicate_sort_key(predicate));
    predicates
        .into_iter()
        .map(|predicate| partial_unique_predicate_sql(entity, predicate))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn partial_unique_predicate_sql(
    entity: &CompiledEntity,
    predicate: &UniqueWhenPredicate,
) -> String {
    match predicate {
        UniqueWhenPredicate::FieldEquals { field, value } => format!(
            "{} = {}",
            field_name(entity, field),
            typed_literal_sql(value, &entity.fields[field].field_type)
        ),
        UniqueWhenPredicate::FieldIsNull { field } => {
            format!("{} IS NULL", field_name(entity, field))
        }
        UniqueWhenPredicate::FieldIsNotNull { field } => {
            format!("{} IS NOT NULL", field_name(entity, field))
        }
        UniqueWhenPredicate::ActiveLifecycle {} => "record_lifecycle = 'active'".to_owned(),
    }
}

fn typed_literal_sql(value: &Value, field_type: &FieldTypeSource) -> String {
    match field_type {
        FieldTypeSource::Boolean => format!(
            "{}::boolean",
            quote_literal(if value.as_bool().expect("validated boolean literal") {
                "true"
            } else {
                "false"
            })
        ),
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::VocabularyCode { .. } => {
            quote_literal(value.as_str().expect("validated text literal"))
        }
        FieldTypeSource::Int64 => format!(
            "{}::bigint",
            quote_literal(&value.as_i64().expect("validated int64 literal").to_string())
        ),
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => format!(
            "{}::numeric({precision},{scale})",
            quote_literal(value.as_str().expect("validated decimal literal"))
        ),
        FieldTypeSource::Date => format!(
            "{}::date",
            quote_literal(value.as_str().expect("validated date literal"))
        ),
        FieldTypeSource::Timestamp => format!(
            "{}::timestamptz",
            quote_literal(value.as_str().expect("validated timestamp literal"))
        ),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => format!(
            "{}::uuid",
            quote_literal(value.as_str().expect("validated UUID literal"))
        ),
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            unreachable!("validated partial unique predicates reject JSON field types")
        }
    }
}

fn unique_when_predicate_sort_key(predicate: &UniqueWhenPredicate) -> String {
    match predicate {
        UniqueWhenPredicate::FieldEquals { field, value } => {
            format!("field:{field}:equals:{}", value)
        }
        UniqueWhenPredicate::FieldIsNull { field } => format!("field:{field}:is_null"),
        UniqueWhenPredicate::FieldIsNotNull { field } => format!("field:{field}:is_not_null"),
        UniqueWhenPredicate::ActiveLifecycle {} => "lifecycle:active".to_owned(),
    }
}

fn sql_type(field_type: &FieldTypeSource) -> String {
    match field_type {
        FieldTypeSource::Boolean => "boolean".to_owned(),
        FieldTypeSource::String { max_length, .. } => format!("varchar({max_length})"),
        FieldTypeSource::Text { .. } | FieldTypeSource::VocabularyCode { .. } => "text".to_owned(),
        FieldTypeSource::Int64 => "bigint".to_owned(),
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => {
            format!("numeric({precision},{scale})")
        }
        FieldTypeSource::Date => "date".to_owned(),
        FieldTypeSource::Timestamp => "timestamptz".to_owned(),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => "uuid".to_owned(),
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            "jsonb".to_owned()
        }
    }
}

fn field_check(identifier: &str, field_type: &FieldTypeSource) -> Option<String> {
    match field_type {
        FieldTypeSource::String { min_length, .. } if *min_length > 0 => {
            Some(format!("char_length({identifier}) >= {min_length}"))
        }
        FieldTypeSource::Text { max_length } => {
            Some(format!("char_length({identifier}) <= {max_length}"))
        }
        FieldTypeSource::VocabularyCode { values, .. } => Some(format!(
            "{identifier} IN ({})",
            values
                .iter()
                .map(|value| quote_literal(value))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        FieldTypeSource::Decimal {
            minimum, maximum, ..
        } => {
            let mut parts = Vec::new();
            if let Some(minimum) = minimum {
                parts.push(format!("{identifier} >= {minimum}"));
            }
            if let Some(maximum) = maximum {
                parts.push(format!("{identifier} <= {maximum}"));
            }
            (!parts.is_empty()).then(|| parts.join(" AND "))
        }
        FieldTypeSource::Crs84Point { precision, bbox } => {
            let mut parts = vec![
                format!("jsonb_typeof({identifier}) = 'object'"),
                format!("{identifier} ->> 'type' = 'Point'"),
                format!("({identifier} - 'type' - 'coordinates') = '{{}}'::jsonb"),
                format!("jsonb_typeof({identifier} -> 'coordinates') = 'array'"),
                format!("jsonb_array_length({identifier} -> 'coordinates') = 2"),
                format!("jsonb_typeof({identifier} -> 'coordinates' -> 0) = 'number'"),
                format!("jsonb_typeof({identifier} -> 'coordinates' -> 1) = 'number'"),
                format!("({identifier} -> 'coordinates' ->> 0)::numeric BETWEEN -180 AND 180"),
                format!("({identifier} -> 'coordinates' ->> 1)::numeric BETWEEN -90 AND 90"),
                format!(
                    "({identifier} -> 'coordinates' ->> 0) ~ {}",
                    quote_literal(&coordinate_pattern(*precision, 180))
                ),
                format!(
                    "({identifier} -> 'coordinates' ->> 1) ~ {}",
                    quote_literal(&coordinate_pattern(*precision, 90))
                ),
            ];
            if let Some(bbox) = bbox {
                parts.push(format!(
                    "({identifier} -> 'coordinates' ->> 0)::numeric BETWEEN {} AND {}",
                    quote_literal(&bbox.west),
                    quote_literal(&bbox.east)
                ));
                parts.push(format!(
                    "({identifier} -> 'coordinates' ->> 1)::numeric BETWEEN {} AND {}",
                    quote_literal(&bbox.south),
                    quote_literal(&bbox.north)
                ));
            }
            Some(parts.join(" AND "))
        }
        FieldTypeSource::Structured { max_bytes, .. } => {
            Some(format!("octet_length({identifier}::text) <= {max_bytes}"))
        }
        _ => None,
    }
}

fn coordinate_pattern(precision: u8, maximum_abs: u16) -> String {
    let integer = match maximum_abs {
        180 => "(0|[1-9][0-9]?|1[0-7][0-9]|180)",
        90 => "(0|[1-9]|[1-8][0-9]|90)",
        _ => unreachable!("only CRS84 coordinate axes are generated"),
    };
    if precision == 0 {
        format!("^-?{integer}$")
    } else {
        format!("^-?{integer}(\\.[0-9]{{1,{precision}}})?$")
    }
}

fn field_list(entity: &CompiledEntity, fields: &[String]) -> String {
    fields
        .iter()
        .map(|field| field_name(entity, field))
        .collect::<Vec<_>>()
        .join(", ")
}

fn field_name(entity: &CompiledEntity, field: &str) -> String {
    quote_identifier(physical_field_name(entity, field))
}

fn physical_field_name<'a>(entity: &'a CompiledEntity, field: &str) -> &'a str {
    if field == entity.canonical_id.id {
        RECORD_ID_COLUMN
    } else {
        &entity.fields[field].physical_name
    }
}

fn logical_field_type(entity: &CompiledEntity, field: &str) -> FieldTypeSource {
    if field == entity.canonical_id.id {
        return entity.canonical_id.field_type.clone();
    }
    entity.fields[field].field_type.clone()
}

fn field_name_with_alias(entity: &CompiledEntity, field: &str, alias: Option<&str>) -> String {
    let field = field_name(entity, field);
    match alias {
        Some(alias) => format!("{alias}.{field}"),
        None => field,
    }
}

fn comparison_operator(operator: ComparisonOperator) -> &'static str {
    match operator {
        ComparisonOperator::LessThan => "<",
        ComparisonOperator::LessThanOrEqual => "<=",
        ComparisonOperator::GreaterThan => ">",
        ComparisonOperator::GreaterThanOrEqual => ">=",
    }
}

pub(crate) fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_json;
    use crate::generated_ddl::{
        drop_spatial_bbox_function_statement, spatial_bbox_function_statement,
        spatial_projection_fields, spatial_projection_statements, DdlStatementKind,
        SPATIAL_BBOX_FUNCTION_NAME,
    };

    #[test]
    fn spatial_projection_helpers_are_deterministic_and_reversible() {
        let registry = compile_spatial_registry();
        let entity = &registry.entities()["site"];
        assert_eq!(
            spatial_projection_fields(entity)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["location"]
        );

        let statements = spatial_projection_statements(entity, "location");
        assert_eq!(statements.add_column.kind, DdlStatementKind::Column);
        assert!(statements
            .add_column
            .sql
            .contains("registry_spatial_ext.geometry(Point,4326)"));
        assert!(statements.add_column.sql.contains("GENERATED ALWAYS AS"));
        assert!(statements
            .add_column
            .sql
            .contains("registry_spatial_ext.ST_SetSRID"));
        assert!(statements
            .add_column
            .sql
            .contains("registry_spatial_ext.ST_MakePoint"));
        assert!(statements.create_index.sql.contains("USING gist"));
        assert!(statements.create_index.sql.contains("WHERE \"rs_spgeom_"));
        assert!(statements
            .drop_index
            .sql
            .starts_with("DROP INDEX IF EXISTS registry_data."));
        assert!(statements.drop_column.sql.contains("DROP COLUMN IF EXISTS"));

        let create_function = spatial_bbox_function_statement();
        assert_eq!(create_function.kind, DdlStatementKind::Function);
        assert!(create_function
            .sql
            .contains("RETURNS registry_spatial_ext.geometry"));
        assert!(create_function.sql.contains("SECURITY INVOKER"));
        assert!(create_function
            .sql
            .contains("registry_spatial_ext.ST_MakeEnvelope"));
        assert!(drop_spatial_bbox_function_statement()
            .sql
            .contains(&format!(
                "DROP FUNCTION IF EXISTS registry_context.{SPATIAL_BBOX_FUNCTION_NAME}()"
            )));
    }

    fn compile_spatial_registry() -> crate::CompiledRegistry {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"spatial-ddl","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://spatial-ddl.example.test"},
              "entities":[{
                "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"internal",
                "fields":[
                  {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
                  {"id":"location","type":"crs84-point","precision":6,"required":true,"classification":"internal"}
                ],
                "geojson":{"geometryField":"location"}
              }],
              "accessProfiles":[{
                "id":"map-reader","default":true,"principalClaim":"principal","grants":[{
                  "entity":"site","operations":["get","list"],"readableFields":["code","location"],
                  "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.25,"maximumLatitudeSpanDegrees":1.5}}
                }]
              }]
            }"#,
        )
        .expect("spatial source parses");
        compile_project(&project, &[], CompileProfile::Authoring).expect("spatial project compiles")
    }
}

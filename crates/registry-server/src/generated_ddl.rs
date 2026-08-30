// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::contract::{
    BoundaryOperator, ComparisonOperator, ConstraintSource, FieldTypeSource, Operation,
    UniqueWhenPredicate, ValidTimeRole,
};
use crate::model::CompiledEntity;
use crate::physical_names::{hex_prefix, PhysicalNameInventory};

const RECORD_ID_COLUMN: &str = "record_id";

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlPolicy {
    pub name: String,
    pub command: PolicyCommand,
    pub access_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub using_expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_expression: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlTable {
    pub entity_id: String,
    pub physical_name: String,
    pub runtime_privileges: BTreeSet<TablePrivilege>,
    pub policies: Vec<DdlPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DdlView {
    pub id: String,
    pub schema: String,
    pub name: String,
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
    pub statements: Vec<DdlStatement>,
    pub tables: Vec<DdlTable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub views: Vec<DdlView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<DdlFunction>,
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

pub(crate) fn generate_ddl(
    entities: &BTreeMap<String, CompiledEntity>,
    names: &PhysicalNameInventory,
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
            columns.push(column_definition(field));
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
    }

    let mut tables = Vec::new();
    let mut views = Vec::new();
    let functions = vec![DdlFunction {
        id: "registry_context.evaluation_date".to_owned(),
        schema: "registry_context".to_owned(),
        name: "evaluation_date".to_owned(),
        arguments: String::new(),
        runtime_execute: true,
    }];
    for entity in entities.values() {
        let runtime_privileges = runtime_privileges(entity, entities);
        let policies = policies(entity, entities);
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
            statements.push(DdlStatement {
                id: format!("entity.{}.policy.{}", entity.id, policy.name),
                kind: DdlStatementKind::Policy,
                sql: policy_sql(&table, policy),
            });
        }
        tables.push(DdlTable {
            entity_id: entity.id.clone(),
            physical_name: entity.physical_table.clone(),
            runtime_privileges,
            policies,
        });
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
        statements,
        tables,
        views,
        functions,
    }
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
            column_definition(field)
        ),
    }
}

fn column_definition(field: &crate::model::CompiledField) -> String {
    let identifier = quote_identifier(&field.physical_name);
    let mut column = format!("{} {}", identifier, sql_type(&field.field_type));
    if field.required {
        column.push_str(" NOT NULL");
    }
    if let Some(check) = field_check(&identifier, &field.field_type) {
        column.push_str(" CHECK (");
        column.push_str(&check);
        column.push(')');
    }
    column
}

fn runtime_privileges(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
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
        )
    }) || path_select_entities(entities).contains(&entity.id)
    {
        privileges.insert(TablePrivilege::Select);
    }
    if operations.contains(&Operation::Create) {
        privileges.insert(TablePrivilege::Insert);
    }
    if operations
        .iter()
        .any(|operation| matches!(operation, Operation::Patch | Operation::Tombstone))
    {
        privileges.insert(TablePrivilege::Update);
    }
    privileges
}

fn policies(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
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
                PolicyCommand::Select => (
                    Some(format!("({authority}) AND record_lifecycle = 'active'")),
                    None,
                ),
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
                using_expression,
                check_expression,
            });
        }
    }
    policies.extend(read_path_policies_for_table(entity, entities));
    policies
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

fn policy_sql(table: &str, policy: &DdlPolicy) -> String {
    let mut sql = format!(
        "CREATE POLICY {} ON registry_data.{table} FOR {}",
        quote_identifier(&policy.name),
        policy.command.as_sql()
    );
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
                "ALTER TABLE registry_data.{table} ADD CONSTRAINT {name} EXCLUDE USING gist ({})",
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

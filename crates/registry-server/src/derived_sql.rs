// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use pg_query::protobuf::{
    node::Node as PgNode, AExpr, Node as PgNodeWrapper, SelectStmt, SetOperation,
};
use pg_query::NodeRef;

use crate::contract::DerivedSource;
use crate::diagnostics::Diagnostic;
use crate::logical_names::default_sql_name;

pub(crate) const MAX_DERIVED_SQL_BYTES: usize = 256 * 1024;

pub(crate) fn validate_derived_sql(
    derived: &DerivedSource,
    sql: &[u8],
    known_relations: &BTreeSet<&str>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(text) = std::str::from_utf8(sql).ok() else {
        errors.push(sql_error(path));
        return;
    };
    if text.is_empty() || text.len() > MAX_DERIVED_SQL_BYTES || text.as_bytes().contains(&0) {
        errors.push(sql_error(path));
        return;
    }
    let Ok(parsed) = pg_query::parse(text) else {
        errors.push(sql_error(path));
        return;
    };
    if parsed.protobuf.stmts.len() != 1 || !parsed.warnings.is_empty() {
        errors.push(sql_error(path));
        return;
    }
    let Some(PgNode::SelectStmt(select)) = root_node(&parsed) else {
        errors.push(sql_error(path));
        return;
    };
    if !valid_select_shape(select) || !declared_output_aliases(select, derived) {
        errors.push(sql_error(path));
        return;
    }
    if !valid_ast(&parsed, known_relations) {
        errors.push(sql_error(path));
    }
}

fn root_node(parsed: &pg_query::ParseResult) -> Option<&PgNode> {
    parsed
        .protobuf
        .stmts
        .first()
        .and_then(|statement| statement.stmt.as_deref())
        .and_then(|statement| statement.node.as_ref())
}

fn valid_select_shape(select: &SelectStmt) -> bool {
    select.into_clause.is_none()
        && select.with_clause.as_ref().is_none_or(|with| {
            !with.recursive
                && with.ctes.iter().all(|cte| {
                    cte.node.as_ref().is_some_and(|node| {
                        matches!(
                            node,
                            PgNode::CommonTableExpr(cte)
                                if cte.ctequery.as_deref().and_then(|query| query.node.as_ref()).is_some_and(|node| matches!(node, PgNode::SelectStmt(select) if valid_select_shape(select)))
                        )
                    })
                })
        })
        && select.locking_clause.is_empty()
        && SetOperation::try_from(select.op).ok() == Some(SetOperation::SetopNone)
}

fn declared_output_aliases(select: &SelectStmt, derived: &DerivedSource) -> bool {
    let expected = std::iter::once(derived.key.as_str())
        .map(str::to_owned)
        .chain(
            derived
                .fields
                .iter()
                .map(|field| default_sql_name(&field.id)),
        )
        .collect::<Vec<_>>();
    if select.target_list.len() != expected.len() {
        return false;
    }
    select
        .target_list
        .iter()
        .zip(expected)
        .all(|(node, expected)| {
            let Some(PgNode::ResTarget(target)) = node.node.as_ref() else {
                return false;
            };
            target.name == expected && target.val.as_deref().is_some_and(no_wildcard)
        })
}

fn no_wildcard(node: &PgNodeWrapper) -> bool {
    !matches!(node.node.as_ref(), Some(PgNode::AStar(_)))
}

fn valid_ast(parsed: &pg_query::ParseResult, known_relations: &BTreeSet<&str>) -> bool {
    let mut statement_nodes = 0_usize;
    for (node, _, _, _) in parsed.protobuf.nodes() {
        match node {
            NodeRef::RangeVar(range) => {
                if !range.catalogname.is_empty()
                    || range.schemaname != "registry_source"
                    || !known_relations.contains(range.relname.as_str())
                    || (!range.relpersistence.is_empty() && range.relpersistence != "p")
                {
                    return false;
                }
            }
            NodeRef::SelectStmt(_) => statement_nodes += 1,
            NodeRef::FuncCall(function) if !safe_function(function) => return false,
            NodeRef::AExpr(expression) if unsafe_schema_operator(expression) => return false,
            node if forbidden_node(node) => return false,
            _ => {}
        }
    }
    statement_nodes >= 1
}

fn unsafe_schema_operator(expression: &AExpr) -> bool {
    node_strings(&expression.name).map_or(true, |names| {
        names.len() != 1
            || !matches!(
                names[0].as_str(),
                "=" | "<>" | "<" | ">" | "<=" | ">=" | "+" | "-" | "*" | "/"
            )
    })
}

fn safe_function(function: &pg_query::protobuf::FuncCall) -> bool {
    let Some(name) = node_strings(&function.funcname) else {
        return false;
    };
    if function.over.is_some() || function.agg_within_group || function.func_variadic {
        return false;
    }
    matches!(
        name.as_slice(),
        [function] if matches!(function.as_str(), "count" | "bool_and" | "every")
    ) || matches!(
        name.as_slice(),
        [schema, function]
            if schema == "pg_catalog"
                && matches!(function.as_str(), "count" | "bool_and" | "every")
    ) || matches!(
        name.as_slice(),
        [schema, function] if schema == "registry_context" && function == "evaluation_date"
    )
}

fn node_strings(nodes: &[pg_query::protobuf::Node]) -> Option<Vec<String>> {
    nodes
        .iter()
        .map(|node| match node.node.as_ref() {
            Some(PgNode::String(value)) => Some(value.sval.clone()),
            _ => None,
        })
        .collect()
}

#[allow(clippy::match_same_arms)]
fn forbidden_node(node: NodeRef<'_>) -> bool {
    matches!(
        node,
        NodeRef::InsertStmt(_)
            | NodeRef::UpdateStmt(_)
            | NodeRef::DeleteStmt(_)
            | NodeRef::MergeStmt(_)
            | NodeRef::CreateTableAsStmt(_)
            | NodeRef::IntoClause(_)
            | NodeRef::CopyStmt(_)
            | NodeRef::LockStmt(_)
            | NodeRef::CallStmt(_)
            | NodeRef::DoStmt(_)
            | NodeRef::CreateStmt(_)
            | NodeRef::ViewStmt(_)
            | NodeRef::CreateFunctionStmt(_)
            | NodeRef::AlterFunctionStmt(_)
            | NodeRef::CreateSchemaStmt(_)
            | NodeRef::AlterObjectSchemaStmt(_)
            | NodeRef::CreateExtensionStmt(_)
            | NodeRef::AlterExtensionStmt(_)
            | NodeRef::DropStmt(_)
            | NodeRef::GrantStmt(_)
            | NodeRef::GrantRoleStmt(_)
            | NodeRef::TransactionStmt(_)
            | NodeRef::VariableSetStmt(_)
            | NodeRef::VariableShowStmt(_)
            | NodeRef::PrepareStmt(_)
            | NodeRef::ExecuteStmt(_)
            | NodeRef::DeallocateStmt(_)
            | NodeRef::DeclareCursorStmt(_)
            | NodeRef::RefreshMatViewStmt(_)
            | NodeRef::ReindexStmt(_)
            | NodeRef::ClusterStmt(_)
            | NodeRef::LoadStmt(_)
            | NodeRef::TableFunc(_)
            | NodeRef::RangeFunction(_)
            | NodeRef::SqlvalueFunction(_)
    )
}

fn sql_error(path: &str) -> Diagnostic {
    Diagnostic::error(
        "derived.sql.invalid",
        path,
        "derived SQL must be one bounded read-only SELECT with declared output aliases over registry_source relations",
    )
}

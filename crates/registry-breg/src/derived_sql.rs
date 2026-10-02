// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use pg_query::protobuf::{
    node::Node as PgNode, AExpr, JsonExprOp, JsonFuncExpr, Node as PgNodeWrapper, SelectStmt,
    SetOperation,
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
    encrypted_columns: &BTreeMap<String, BTreeSet<String>>,
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
    refuse_encrypted_columns(&parsed, encrypted_columns, path, errors);
}

/// Refuse any column reference that resolves to an encrypted field. The
/// registry_source layer never exposes encrypted columns, so such a reference
/// could only fail at runtime; refusing it at compile keeps the derived layer
/// honest. Map keys are relation sql names and values are the logical column
/// names of each entity's encrypted fields.
fn refuse_encrypted_columns(
    parsed: &pg_query::ParseResult,
    encrypted_columns: &BTreeMap<String, BTreeSet<String>>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if encrypted_columns.is_empty() {
        return;
    }
    let qualified_relations = source_relation_qualifiers(parsed);
    let cte_outputs = cte_output_qualifiers(parsed);
    for node in raw_nodes(parsed) {
        let NodeRef::ColumnRef(column) = node else {
            continue;
        };
        let names: Vec<String> = column
            .fields
            .iter()
            .filter_map(|field| match field.node.as_ref() {
                Some(PgNode::String(value)) => Some(value.sval.clone()),
                _ => None,
            })
            .collect();
        let Some(last) = names.last() else {
            continue;
        };
        let matches = match names.as_slice() {
            [schema, relation, _column] if schema == "registry_source" => encrypted_columns
                .get(relation.as_str())
                .is_some_and(|columns| columns.contains(last)),
            [qualifier, _column] if qualified_relations.contains_key(qualifier) => {
                qualified_relations[qualifier].iter().any(|relation| {
                    encrypted_columns
                        .get(relation)
                        .is_some_and(|columns| columns.contains(last))
                })
            }
            [qualifier, _column]
                if cte_outputs
                    .get(qualifier)
                    .is_some_and(|columns| columns.contains(last)) =>
            {
                false
            }
            // An unqualified reference, or a qualifier not owned by a direct
            // registry_source range, cannot be resolved without full scope
            // analysis. Refuse it conservatively against every source.
            _ => encrypted_columns
                .values()
                .any(|columns| columns.contains(last)),
        };
        if matches {
            errors.push(Diagnostic::error(
                "derived.sql.encrypted_column",
                path,
                "derived SQL cannot reference an encrypted column; registry_source views never expose it",
            ));
            return;
        }
    }
}

/// Map each direct `registry_source` relation and authored alias back to the
/// source relation it qualifies. A qualifier can occur in nested scopes, so
/// retain every candidate and refuse when any candidate owns the encrypted
/// column rather than pretending the query has one flat namespace.
fn source_relation_qualifiers(
    parsed: &pg_query::ParseResult,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut qualifiers = BTreeMap::<String, BTreeSet<String>>::new();
    for node in raw_nodes(parsed) {
        let NodeRef::RangeVar(range) = node else {
            continue;
        };
        if !range.catalogname.is_empty() || range.schemaname != "registry_source" {
            continue;
        }
        qualifiers
            .entry(range.relname.clone())
            .or_default()
            .insert(range.relname.clone());
        if let Some(alias) = &range.alias {
            qualifiers
                .entry(alias.aliasname.clone())
                .or_default()
                .insert(range.relname.clone());
        }
    }
    qualifiers
}

/// Map each CTE name and authored range alias to output columns declared by an
/// alias or unambiguously inherited from a simple column reference. References
/// inside the CTE are still checked on their own against source relations;
/// this only prevents the outer `cte.column` reference from being mistaken
/// for an unresolved source column with the same name.
fn cte_output_qualifiers(parsed: &pg_query::ParseResult) -> BTreeMap<String, BTreeSet<String>> {
    let ctes = raw_nodes(parsed)
        .into_iter()
        .filter_map(|node| {
            let NodeRef::CommonTableExpr(cte) = node else {
                return None;
            };
            let column_names = if cte.aliascolnames.is_empty() {
                let Some(PgNode::SelectStmt(select)) = cte
                    .ctequery
                    .as_deref()
                    .and_then(|query| query.node.as_ref())
                else {
                    return None;
                };
                select
                    .target_list
                    .iter()
                    .map(cte_target_name)
                    .collect::<Option<Vec<_>>>()?
            } else {
                node_strings(&cte.aliascolnames)?
            };
            let columns = column_names.iter().cloned().collect::<BTreeSet<_>>();
            (!columns.is_empty() && columns.len() == column_names.len())
                .then(|| (cte.ctename.clone(), columns))
        })
        .collect::<BTreeMap<_, _>>();

    let mut qualifiers = BTreeMap::<String, BTreeSet<String>>::new();
    for node in raw_nodes(parsed) {
        let NodeRef::RangeVar(range) = node else {
            continue;
        };
        if !range.catalogname.is_empty() || !range.schemaname.is_empty() {
            continue;
        }
        let Some(columns) = ctes.get(&range.relname) else {
            continue;
        };
        qualifiers
            .entry(range.relname.clone())
            .or_default()
            .extend(columns.iter().cloned());
        if let Some(alias) = &range.alias {
            qualifiers
                .entry(alias.aliasname.clone())
                .or_default()
                .extend(columns.iter().cloned());
        }
    }
    qualifiers
}

fn cte_target_name(node: &PgNodeWrapper) -> Option<String> {
    let Some(PgNode::ResTarget(target)) = node.node.as_ref() else {
        return None;
    };
    if !target.name.is_empty() {
        return Some(target.name.clone());
    }
    let Some(PgNode::ColumnRef(column)) = target.val.as_deref()?.node.as_ref() else {
        return None;
    };
    node_strings(&column.fields)?.pop()
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
        && !select.group_distinct
        && select.window_clause.is_empty()
        && select.values_lists.is_empty()
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
    let mut cte_names = BTreeSet::new();
    for node in raw_nodes(parsed) {
        if let NodeRef::CommonTableExpr(cte) = node {
            if cte.ctename.is_empty()
                || cte.cterecursive
                || cte.search_clause.is_some()
                || cte.cycle_clause.is_some()
                || !cte_names.insert(cte.ctename.as_str())
            {
                return false;
            }
        }
    }
    let mut statement_nodes = 0_usize;
    for node in raw_nodes(parsed) {
        match node {
            NodeRef::RangeVar(range) => {
                let source_relation = range.catalogname.is_empty()
                    && range.schemaname == "registry_source"
                    && known_relations.contains(range.relname.as_str());
                let cte_relation = range.catalogname.is_empty()
                    && range.schemaname.is_empty()
                    && cte_names.contains(range.relname.as_str());
                if (!source_relation && !cte_relation)
                    || (!range.relpersistence.is_empty() && range.relpersistence != "p")
                    || range
                        .alias
                        .as_ref()
                        .is_some_and(|alias| !alias.colnames.is_empty())
                {
                    return false;
                }
            }
            NodeRef::SelectStmt(select) => {
                if !valid_select_shape(select) {
                    return false;
                }
                statement_nodes += 1;
            }
            NodeRef::FuncCall(function) if !safe_function(function) => return false,
            NodeRef::AExpr(expression) if unsafe_schema_operator(expression) => return false,
            NodeRef::JsonFuncExpr(function) if !safe_json_function(function) => return false,
            NodeRef::SubLink(link) if !safe_scalar_subquery(link) => return false,
            NodeRef::SortBy(sort) if !sort.use_op.is_empty() => return false,
            NodeRef::ResTarget(target) if !target.indirection.is_empty() => return false,
            NodeRef::ColumnRef(column) if !safe_column_ref(column) => return false,
            NodeRef::JoinExpr(join) if unsafe_implicit_join_columns(join) => return false,
            node if allowed_raw_node(node) => {}
            _ => return false,
        }
    }
    statement_nodes >= 1
}

/// `pg_query` intentionally walks only a subset of raw grammar. Extend that
/// traversal for every child-bearing node admitted below so validation and
/// encrypted-column checks see the same complete expression tree.
fn raw_nodes(parsed: &pg_query::ParseResult) -> Vec<NodeRef<'_>> {
    let mut nodes = parsed
        .protobuf
        .nodes()
        .into_iter()
        .map(|(node, _, _, _)| node)
        .collect::<Vec<_>>();
    let mut index = 0;
    while index < nodes.len() {
        match nodes[index] {
            NodeRef::SelectStmt(select) => {
                extend_raw_nodes(&mut nodes, select.distinct_clause.iter());
                extend_optional_raw_node(&mut nodes, select.limit_offset.as_deref());
                extend_optional_raw_node(&mut nodes, select.limit_count.as_deref());
            }
            NodeRef::FuncCall(function) => {
                extend_raw_nodes(&mut nodes, function.agg_order.iter());
                extend_optional_raw_node(&mut nodes, function.agg_filter.as_deref());
            }
            NodeRef::CaseExpr(expression) => {
                extend_optional_raw_node(&mut nodes, expression.arg.as_deref());
            }
            NodeRef::JsonFuncExpr(function) => {
                if let Some(context) = function.context_item.as_deref() {
                    extend_json_value_nodes(&mut nodes, context);
                }
                extend_optional_raw_node(&mut nodes, function.pathspec.as_deref());
                extend_raw_nodes(&mut nodes, function.passing.iter());
                if let Some(behavior) = function.on_empty.as_deref() {
                    extend_optional_raw_node(&mut nodes, behavior.expr.as_deref());
                }
                if let Some(behavior) = function.on_error.as_deref() {
                    extend_optional_raw_node(&mut nodes, behavior.expr.as_deref());
                }
            }
            NodeRef::JsonArgument(argument) => {
                if let Some(value) = argument.val.as_deref() {
                    extend_json_value_nodes(&mut nodes, value);
                }
            }
            _ => {}
        }
        index += 1;
    }
    nodes
}

fn extend_json_value_nodes<'a>(
    nodes: &mut Vec<NodeRef<'a>>,
    value: &'a pg_query::protobuf::JsonValueExpr,
) {
    extend_optional_raw_node(nodes, value.raw_expr.as_deref());
    extend_optional_raw_node(nodes, value.formatted_expr.as_deref());
}

fn extend_raw_nodes<'a, I>(nodes: &mut Vec<NodeRef<'a>>, children: I)
where
    I: IntoIterator<Item = &'a PgNodeWrapper>,
{
    for child in children {
        extend_optional_raw_node(nodes, Some(child));
    }
}

fn extend_optional_raw_node<'a>(nodes: &mut Vec<NodeRef<'a>>, child: Option<&'a PgNodeWrapper>) {
    if let Some(child) = child.and_then(|child| child.node.as_ref()) {
        nodes.extend(child.nodes().into_iter().map(|(node, _, _, _)| node));
    }
}

fn unsafe_schema_operator(expression: &AExpr) -> bool {
    node_strings(&expression.name).is_none_or(|names| {
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

fn safe_json_function(function: &JsonFuncExpr) -> bool {
    matches!(
        JsonExprOp::try_from(function.op),
        Ok(JsonExprOp::JsonValueOp | JsonExprOp::JsonExistsOp)
    ) && function.output.as_ref().is_none_or(|output| {
        output
            .type_name
            .as_ref()
            .is_none_or(safe_json_returning_type)
    })
}

fn safe_json_returning_type(type_name: &pg_query::protobuf::TypeName) -> bool {
    if type_name.setof
        || type_name.pct_type
        || !type_name.array_bounds.is_empty()
        || !type_name
            .typmods
            .iter()
            .all(|modifier| matches!(modifier.node.as_ref(), Some(PgNode::AConst(_))))
    {
        return false;
    }
    let Some(name) = node_strings(&type_name.names) else {
        return false;
    };
    let scalar = match name.as_slice() {
        [scalar] => scalar.as_str(),
        [schema, scalar] if schema == "pg_catalog" => scalar.as_str(),
        _ => return false,
    };
    matches!(
        scalar,
        "bool"
            | "int2"
            | "int4"
            | "int8"
            | "numeric"
            | "text"
            | "varchar"
            | "bpchar"
            | "date"
            | "timestamptz"
            | "uuid"
    )
}

fn safe_scalar_subquery(link: &pg_query::protobuf::SubLink) -> bool {
    link.testexpr.is_none()
        && link.oper_name.is_empty()
        && pg_query::protobuf::SubLinkType::try_from(link.sub_link_type)
            .is_ok_and(|kind| kind == pg_query::protobuf::SubLinkType::ExprSublink)
}

fn safe_column_ref(column: &pg_query::protobuf::ColumnRef) -> bool {
    (1..=3).contains(&column.fields.len())
        && column
            .fields
            .iter()
            .all(|field| matches!(field.node.as_ref(), Some(PgNode::String(_))))
}

fn unsafe_implicit_join_columns(join: &pg_query::protobuf::JoinExpr) -> bool {
    join.is_natural
        || !join.using_clause.is_empty()
        || join.join_using_alias.is_some()
        || join
            .alias
            .as_ref()
            .is_some_and(|alias| !alias.colnames.is_empty())
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

/// Raw grammar is an input boundary. Keep this as an allowlist so a new or
/// previously unhandled `pg_query` node is refused until its semantics and
/// traversal have been reviewed here.
fn allowed_raw_node(node: NodeRef<'_>) -> bool {
    matches!(
        node,
        NodeRef::SelectStmt(_)
            | NodeRef::RangeVar(_)
            | NodeRef::CommonTableExpr(_)
            | NodeRef::ResTarget(_)
            | NodeRef::ColumnRef(_)
            | NodeRef::AConst(_)
            | NodeRef::AExpr(_)
            | NodeRef::BoolExpr(_)
            | NodeRef::NullTest(_)
            | NodeRef::BooleanTest(_)
            | NodeRef::TypeCast(_)
            | NodeRef::FuncCall(_)
            | NodeRef::CaseExpr(_)
            | NodeRef::CaseWhen(_)
            | NodeRef::CaseTestExpr(_)
            | NodeRef::CoalesceExpr(_)
            | NodeRef::JoinExpr(_)
            | NodeRef::RangeSubselect(_)
            | NodeRef::SubLink(_)
            | NodeRef::SortBy(_)
            | NodeRef::List(_)
            | NodeRef::RowExpr(_)
            | NodeRef::JsonFuncExpr(_)
            | NodeRef::JsonArgument(_)
    )
}

fn sql_error(path: &str) -> Diagnostic {
    Diagnostic::error(
        "derived.sql.invalid",
        path,
        "derived SQL must be one bounded read-only SELECT with declared output aliases over registry_source relations",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts(sql: &str) -> bool {
        let parsed = pg_query::parse(sql)
            .unwrap_or_else(|error| panic!("test SQL did not parse: {sql}: {error}"));
        valid_ast(&parsed, &BTreeSet::from(["household", "member"]))
    }

    #[test]
    fn raw_node_allowlist_preserves_the_supported_select_surface() {
        let accepted = [
            "SELECT h.id FROM registry_source.household h",
            "SELECT DISTINCT h.id FROM registry_source.household h LIMIT 10 OFFSET 1",
            "SELECT (SELECT m.id FROM registry_source.member m WHERE m.id = h.id) FROM registry_source.household h",
            "SELECT CASE WHEN h.active IS TRUE THEN h.id ELSE NULL END FROM registry_source.household h",
            "SELECT coalesce(h.label, 'unknown') FROM registry_source.household h",
            "SELECT h.id FROM registry_source.household h LEFT JOIN registry_source.member m ON m.id = h.id",
            "WITH selected AS (SELECT h.id AS id FROM registry_source.household h) SELECT s.id FROM selected s",
            "WITH selected AS (WITH inner_selected AS (SELECT h.id AS id FROM registry_source.household h) SELECT i.id FROM inner_selected i) SELECT s.id FROM selected s",
            "SELECT count(*) FILTER (WHERE m.active IS TRUE) > 0 FROM registry_source.household h LEFT JOIN registry_source.member m ON m.id = h.id GROUP BY h.id",
            "SELECT count(*) FILTER (WHERE m.valid_from <= registry_context.evaluation_date() AND (m.valid_to IS NULL OR registry_context.evaluation_date() < m.valid_to)) FROM registry_source.household h LEFT JOIN registry_source.member m ON m.id = h.id GROUP BY h.id",
        ];

        for sql in accepted {
            assert!(accepts(sql), "supported derived SELECT was refused: {sql}");
        }
    }

    #[test]
    fn json_value_and_json_exists_are_allowed() {
        for sql in [
            "SELECT JSON_VALUE(h.document, '$.name') FROM registry_source.household h",
            "SELECT JSON_VALUE(h.document, '$.count' RETURNING int DEFAULT 0 ON ERROR) FROM registry_source.household h",
            "SELECT JSON_VALUE(h.document, '$.count' RETURNING bigint) FROM registry_source.household h",
            "SELECT JSON_VALUE(h.document, '$.amount' RETURNING numeric(5, 2)) FROM registry_source.household h",
            "SELECT JSON_VALUE(h.document, '$.name' RETURNING text DEFAULT 'fallback' ON EMPTY) FROM registry_source.household h",
            "SELECT JSON_EXISTS(h.document, '$.name' TRUE ON ERROR) FROM registry_source.household h",
            "SELECT JSON_EXISTS(h.document, '$?(@ == $value)' PASSING h.id AS value FALSE ON ERROR) FROM registry_source.household h",
        ] {
            assert!(
                accepts(sql),
                "supported SQL/JSON function was refused: {sql}"
            );
        }
    }

    #[test]
    fn raw_node_allowlist_refuses_unreviewed_sql_json_xml_and_hidden_descendants() {
        for sql in [
            "SELECT JSON_QUERY(h.document, '$.name') FROM registry_source.household h",
            "SELECT j.value FROM registry_source.household h, JSON_TABLE(h.document, '$[*]' COLUMNS (value text PATH '$')) AS j",
            "SELECT x.value FROM registry_source.household h, XMLTABLE('/row' PASSING h.document COLUMNS value text PATH '.') AS x",
            "SELECT JSON_ARRAYAGG(h.id) FROM registry_source.household h",
            "SELECT JSON_OBJECTAGG(h.id VALUE h.document) FROM registry_source.household h",
            "SELECT JSON_ARRAY(h.id) FROM registry_source.household h",
            "SELECT JSON_ARRAY(SELECT m.id FROM registry_source.member m) FROM registry_source.household h",
            "SELECT JSON_OBJECT('id' VALUE h.id) FROM registry_source.household h",
            "SELECT XMLCONCAT(h.document) FROM registry_source.household h",
            "SELECT XMLELEMENT(NAME item, h.document) FROM registry_source.household h",
            "SELECT XMLFOREST(h.document AS item) FROM registry_source.household h",
            "SELECT XMLPARSE(DOCUMENT h.document) FROM registry_source.household h",
            "SELECT XMLPI(NAME item, h.document) FROM registry_source.household h",
            "SELECT XMLROOT(h.document, VERSION '1.0') FROM registry_source.household h",
            "SELECT XMLSERIALIZE(DOCUMENT h.document AS text) FROM registry_source.household h",
            "SELECT JSON_VALUE(lower(h.document), '$.name') FROM registry_source.household h",
            "SELECT JSON_EXISTS((SELECT p.document FROM pg_catalog.pg_class p), '$.name') FROM registry_source.household h",
            "SELECT JSON_EXISTS(h.document, '$?(@ == $value)' PASSING lower(h.document) AS value) FROM registry_source.household h",
            "SELECT JSON_VALUE(h.document, '$.name' DEFAULT lower(h.document) ON ERROR) FROM registry_source.household h",
            "SELECT JSON_VALUE(h.document, '$.name' RETURNING private.custom_type) FROM registry_source.household h",
            "SELECT JSON_VALUE(h.document, '$.name' RETURNING custom_type) FROM registry_source.household h",
            "WITH hidden AS (SELECT pg_read_file('/etc/passwd') AS value FROM registry_source.household h) SELECT h.id FROM registry_source.household h",
            "WITH hidden AS (SELECT p.oid AS id FROM pg_catalog.pg_class p) SELECT hidden.id FROM hidden",
            "SELECT h.id FROM registry_source.household h JOIN registry_source.member m USING (id)",
            "SELECT h.id FROM registry_source.household h NATURAL JOIN registry_source.member m",
            "SELECT h.renamed_document FROM registry_source.household AS h(renamed_id, renamed_document)",
            "SELECT joined.renamed_id FROM (registry_source.household h JOIN registry_source.member m ON m.id = h.id) AS joined(renamed_id)",
        ] {
            assert!(!accepts(sql), "unsupported SQL/JSON or XML grammar was accepted: {sql}");
        }
    }

    #[test]
    fn supplemental_descendants_cannot_hide_encrypted_columns() {
        let encrypted_columns = BTreeMap::from([(
            "household".to_owned(),
            BTreeSet::from(["document".to_owned()]),
        )]);
        for sql in [
            "SELECT JSON_VALUE(h.document, '$.name') FROM registry_source.household h",
            "WITH hidden AS (SELECT h.id AS id, h.document AS secret FROM registry_source.household h) SELECT hidden.id FROM hidden",
        ] {
            let parsed = pg_query::parse(sql).expect("test SQL parses");
            let mut errors = Vec::new();

            refuse_encrypted_columns(
                &parsed,
                &encrypted_columns,
                "entities[household].derived[summary].sql",
                &mut errors,
            );

            assert!(
                errors
                    .iter()
                    .any(|diagnostic| diagnostic.code == "derived.sql.encrypted_column"),
                "encrypted column hidden in derived SQL was accepted: {sql}"
            );
        }
    }

    #[test]
    fn unlisted_raw_grammar_fails_closed() {
        assert!(!accepts(
            "SELECT ARRAY[h.id] FROM registry_source.household h"
        ));
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use pg_query::protobuf::{
    node::Node as PgNode, AExpr, JsonExprOp, JsonFuncExpr, Node as PgNodeWrapper, SelectStmt,
    SetOperation,
};
use pg_query::NodeRef;

use crate::contract::DerivedSource;
use crate::diagnostics::Diagnostic;
use crate::logical_names::canonical_sql_name;

pub(crate) const MAX_DERIVED_SQL_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DerivedSqlDependencies {
    pub source_relations: BTreeSet<String>,
    pub uses_evaluation_date: bool,
}

pub(crate) type DerivedSourceColumns = BTreeMap<String, BTreeSet<String>>;

/// Extract dependency metadata from SQL which has already passed
/// [`validate_derived_sql`]. Compilation only calls this after validation
/// succeeds, so unparseable SQL panics rather than yield an empty inventory
/// that would silently drop source entities from the statistical dependency
/// closure.
pub(crate) fn derived_sql_dependencies(sql: &[u8]) -> DerivedSqlDependencies {
    const VALIDATED: &str = "derived SQL was validated before its dependency inventory";
    let text = std::str::from_utf8(sql).expect(VALIDATED);
    let parsed = pg_query::parse(text).expect(VALIDATED);
    let mut dependencies = DerivedSqlDependencies::default();
    for node in raw_nodes(&parsed) {
        match node {
            NodeRef::RangeVar(range)
                if range.catalogname.is_empty() && range.schemaname == "registry_source" =>
            {
                dependencies.source_relations.insert(range.relname.clone());
            }
            NodeRef::FuncCall(function)
                if node_strings(&function.funcname).is_some_and(|name| {
                    name.as_slice() == ["registry_context", "evaluation_date"]
                }) =>
            {
                dependencies.uses_evaluation_date = true;
            }
            _ => {}
        }
    }
    dependencies
}

/// Resolve the stored source columns read by SQL which has already passed
/// [`validate_derived_sql`]. This reuses the validator's lexical scopes so
/// aliases, correlated subqueries, and shadowing bind to the same source
/// relation at digest compilation as they do at admission.
pub(crate) fn derived_sql_source_columns(
    sql: &[u8],
    source_columns: &BTreeMap<String, BTreeSet<String>>,
) -> DerivedSourceColumns {
    const VALIDATED: &str = "derived SQL was validated before its source-column inventory";
    let text = std::str::from_utf8(sql).expect(VALIDATED);
    let parsed = pg_query::parse(text).expect(VALIDATED);
    let Some(PgNode::SelectStmt(select)) = root_node(&parsed) else {
        panic!("{VALIDATED}");
    };
    let dependencies = RefCell::new(BTreeMap::new());
    assert!(validate_select_columns(
        select,
        source_columns,
        &BTreeMap::new(),
        &[],
        &dependencies,
    ));
    dependencies.into_inner()
}

pub(crate) fn validate_derived_sql(
    derived: &DerivedSource,
    sql: &[u8],
    source_columns: &BTreeMap<String, BTreeSet<String>>,
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
    let known_relations = source_columns.keys().map(String::as_str).collect();
    if !valid_ast(&parsed, &known_relations) || !valid_column_references(select, source_columns) {
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
                .map(|field| canonical_sql_name(&field.id)),
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

#[derive(Clone)]
struct RelationBinding {
    qualifiers: Vec<Vec<String>>,
    columns: BTreeSet<String>,
    source_columns: DerivedSourceColumns,
}

#[derive(Clone, Default)]
struct QueryScope {
    qualified: BTreeMap<Vec<String>, BTreeSet<String>>,
    qualified_source_columns: BTreeMap<Vec<String>, DerivedSourceColumns>,
    relations: Vec<RelationBinding>,
}

impl QueryScope {
    fn from_bindings(bindings: Vec<RelationBinding>) -> Option<Self> {
        let mut scope = Self::default();
        for binding in bindings {
            for qualifier in &binding.qualifiers {
                if scope
                    .qualified
                    .insert(qualifier.clone(), binding.columns.clone())
                    .is_some()
                {
                    return None;
                }
                scope
                    .qualified_source_columns
                    .insert(qualifier.clone(), binding.source_columns.clone());
            }
            scope.relations.push(binding);
        }
        Some(scope)
    }
}

fn valid_column_references(
    select: &SelectStmt,
    source_columns: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    validate_select_columns(
        select,
        source_columns,
        &BTreeMap::new(),
        &[],
        &RefCell::new(BTreeMap::new()),
    )
}

fn validate_select_columns(
    select: &SelectStmt,
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    inherited_ctes: &BTreeMap<String, BTreeSet<String>>,
    outer_scopes: &[QueryScope],
    dependencies: &RefCell<DerivedSourceColumns>,
) -> bool {
    let mut ctes = inherited_ctes.clone();
    if let Some(with) = &select.with_clause {
        for node in &with.ctes {
            let Some(PgNode::CommonTableExpr(cte)) = node.node.as_ref() else {
                return false;
            };
            let Some(PgNode::SelectStmt(query)) = cte
                .ctequery
                .as_deref()
                .and_then(|query| query.node.as_ref())
            else {
                return false;
            };
            if !validate_select_columns(query, source_columns, &ctes, outer_scopes, dependencies) {
                return false;
            }
            let Some(columns) = select_output_columns(query, &cte.aliascolnames) else {
                return false;
            };
            ctes.insert(cte.ctename.clone(), columns);
        }
    }

    let mut bindings = Vec::new();
    for node in &select.from_clause {
        let Some(mut next) = collect_from_bindings(
            node,
            source_columns,
            &ctes,
            outer_scopes,
            &bindings,
            dependencies,
        ) else {
            return false;
        };
        bindings.append(&mut next);
    }
    let Some(current_scope) = QueryScope::from_bindings(bindings) else {
        return false;
    };
    let mut scopes = outer_scopes.to_vec();
    scopes.push(current_scope);

    let no_aliases = BTreeSet::new();
    if !select.target_list.iter().all(|target| {
        target.node.as_ref().is_some_and(|node| {
            matches!(node, PgNode::ResTarget(target) if validate_optional_expression(
                target.val.as_deref(), source_columns, &ctes, &scopes, &no_aliases, dependencies
            ))
        })
    }) || !validate_optional_expression(
        select.where_clause.as_deref(),
        source_columns,
        &ctes,
        &scopes,
        &no_aliases,
        dependencies,
    ) || !validate_optional_expression(
        select.having_clause.as_deref(),
        source_columns,
        &ctes,
        &scopes,
        &no_aliases,
        dependencies,
    ) || !validate_optional_expression(
        select.limit_offset.as_deref(),
        source_columns,
        &ctes,
        &scopes,
        &no_aliases,
        dependencies,
    ) || !validate_optional_expression(
        select.limit_count.as_deref(),
        source_columns,
        &ctes,
        &scopes,
        &no_aliases,
        dependencies,
    ) {
        return false;
    }

    let output_aliases = select
        .target_list
        .iter()
        .filter_map(|target| match target.node.as_ref() {
            Some(PgNode::ResTarget(target)) if !target.name.is_empty() => Some(target.name.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    select
        .distinct_clause
        .iter()
        .chain(&select.group_clause)
        .all(|node| {
            validate_sql92_expression(
                node,
                source_columns,
                &ctes,
                &scopes,
                &output_aliases,
                dependencies,
            )
        })
        && select.sort_clause.iter().all(|node| {
            validate_sql92_expression(
                node,
                source_columns,
                &ctes,
                &scopes,
                &output_aliases,
                dependencies,
            )
        })
}

fn validate_sql92_expression(
    node: &PgNodeWrapper,
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    ctes: &BTreeMap<String, BTreeSet<String>>,
    scopes: &[QueryScope],
    output_aliases: &BTreeSet<String>,
    dependencies: &RefCell<DerivedSourceColumns>,
) -> bool {
    // Plain DISTINCT is represented by a null placeholder; DISTINCT ON
    // entries carry the expressions that need scope validation.
    if node.node.is_none() {
        return true;
    }
    let expression = match node.node.as_ref() {
        Some(PgNode::SortBy(sort)) => sort.node.as_deref().unwrap_or(node),
        _ => node,
    };
    if matches!(
        expression.node.as_ref(),
        Some(PgNode::ColumnRef(column))
            if node_strings(&column.fields).is_some_and(|names|
                matches!(names.as_slice(), [name] if output_aliases.contains(name)))
    ) {
        return true;
    }
    validate_expression(
        node,
        source_columns,
        ctes,
        scopes,
        &BTreeSet::new(),
        dependencies,
    )
}

fn collect_from_bindings(
    node: &PgNodeWrapper,
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    ctes: &BTreeMap<String, BTreeSet<String>>,
    outer_scopes: &[QueryScope],
    preceding: &[RelationBinding],
    dependencies: &RefCell<DerivedSourceColumns>,
) -> Option<Vec<RelationBinding>> {
    match node.node.as_ref()? {
        PgNode::RangeVar(range) => {
            let (columns, source_qualifier) =
                if range.catalogname.is_empty() && range.schemaname == "registry_source" {
                    (source_columns.get(&range.relname)?.clone(), true)
                } else if range.catalogname.is_empty() && range.schemaname.is_empty() {
                    (ctes.get(&range.relname)?.clone(), false)
                } else {
                    return None;
                };
            let qualifiers = if let Some(alias) = &range.alias {
                vec![vec![alias.aliasname.clone()]]
            } else if source_qualifier {
                vec![
                    vec![range.relname.clone()],
                    vec![range.schemaname.clone(), range.relname.clone()],
                ]
            } else {
                vec![vec![range.relname.clone()]]
            };
            let source_columns = if source_qualifier {
                BTreeMap::from([(range.relname.clone(), columns.clone())])
            } else {
                BTreeMap::new()
            };
            Some(vec![RelationBinding {
                qualifiers,
                source_columns,
                columns,
            }])
        }
        PgNode::RangeSubselect(range) => {
            let Some(PgNode::SelectStmt(query)) = range
                .subquery
                .as_deref()
                .and_then(|query| query.node.as_ref())
            else {
                return None;
            };
            let mut nested_outer = outer_scopes.to_vec();
            if range.lateral && !preceding.is_empty() {
                nested_outer.push(QueryScope::from_bindings(preceding.to_vec())?);
            }
            if !validate_select_columns(query, source_columns, ctes, &nested_outer, dependencies) {
                return None;
            }
            let alias_columns = range
                .alias
                .as_ref()
                .map_or(&[][..], |alias| alias.colnames.as_slice());
            let columns = select_output_columns(query, alias_columns)?;
            let qualifiers = range
                .alias
                .as_ref()
                .map(|alias| vec![vec![alias.aliasname.clone()]])
                .unwrap_or_default();
            Some(vec![RelationBinding {
                qualifiers,
                columns,
                source_columns: BTreeMap::new(),
            }])
        }
        PgNode::JoinExpr(join) => {
            let mut left = collect_from_bindings(
                join.larg.as_deref()?,
                source_columns,
                ctes,
                outer_scopes,
                preceding,
                dependencies,
            )?;
            let mut visible_to_right = preceding.to_vec();
            visible_to_right.extend(left.iter().cloned());
            let mut right = collect_from_bindings(
                join.rarg.as_deref()?,
                source_columns,
                ctes,
                outer_scopes,
                &visible_to_right,
                dependencies,
            )?;
            let mut joined = left.clone();
            joined.extend(right.iter().cloned());
            let mut join_scopes = outer_scopes.to_vec();
            join_scopes.push(QueryScope::from_bindings(joined.clone())?);
            if !validate_optional_expression(
                join.quals.as_deref(),
                source_columns,
                ctes,
                &join_scopes,
                &BTreeSet::new(),
                dependencies,
            ) {
                return None;
            }
            if let Some(alias) = &join.alias {
                let source_columns = left
                    .iter()
                    .chain(&right)
                    .flat_map(|binding| binding.source_columns.iter())
                    .fold(BTreeMap::new(), |mut all, (relation, fields)| {
                        all.entry(relation.clone())
                            .or_insert_with(BTreeSet::new)
                            .extend(fields.iter().cloned());
                        all
                    });
                let columns = left
                    .drain(..)
                    .chain(right.drain(..))
                    .flat_map(|binding| binding.columns)
                    .collect();
                Some(vec![RelationBinding {
                    qualifiers: vec![vec![alias.aliasname.clone()]],
                    columns,
                    source_columns,
                }])
            } else {
                left.append(&mut right);
                Some(left)
            }
        }
        _ => None,
    }
}

fn select_output_columns(
    select: &SelectStmt,
    aliases: &[PgNodeWrapper],
) -> Option<BTreeSet<String>> {
    if aliases.len() > select.target_list.len() {
        return None;
    }
    let aliases = node_strings(aliases)?;
    let names = select
        .target_list
        .iter()
        .enumerate()
        .map(|(index, target)| {
            aliases
                .get(index)
                .cloned()
                .or_else(|| cte_target_name(target))
        })
        .collect::<Option<Vec<_>>>()?;
    let columns = names.iter().cloned().collect::<BTreeSet<_>>();
    (columns.len() == names.len()).then_some(columns)
}

fn validate_optional_expression(
    node: Option<&PgNodeWrapper>,
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    ctes: &BTreeMap<String, BTreeSet<String>>,
    scopes: &[QueryScope],
    output_aliases: &BTreeSet<String>,
    dependencies: &RefCell<DerivedSourceColumns>,
) -> bool {
    node.is_none_or(|node| {
        validate_expression(
            node,
            source_columns,
            ctes,
            scopes,
            output_aliases,
            dependencies,
        )
    })
}

fn validate_expressions(
    nodes: &[PgNodeWrapper],
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    ctes: &BTreeMap<String, BTreeSet<String>>,
    scopes: &[QueryScope],
    output_aliases: &BTreeSet<String>,
    dependencies: &RefCell<DerivedSourceColumns>,
) -> bool {
    nodes.iter().all(|node| {
        validate_expression(
            node,
            source_columns,
            ctes,
            scopes,
            output_aliases,
            dependencies,
        )
    })
}

fn validate_json_value_expression(
    value: &pg_query::protobuf::JsonValueExpr,
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    ctes: &BTreeMap<String, BTreeSet<String>>,
    scopes: &[QueryScope],
    output_aliases: &BTreeSet<String>,
    dependencies: &RefCell<DerivedSourceColumns>,
) -> bool {
    validate_optional_expression(
        value.raw_expr.as_deref(),
        source_columns,
        ctes,
        scopes,
        output_aliases,
        dependencies,
    ) && validate_optional_expression(
        value.formatted_expr.as_deref(),
        source_columns,
        ctes,
        scopes,
        output_aliases,
        dependencies,
    )
}

fn validate_expression(
    node: &PgNodeWrapper,
    source_columns: &BTreeMap<String, BTreeSet<String>>,
    ctes: &BTreeMap<String, BTreeSet<String>>,
    scopes: &[QueryScope],
    output_aliases: &BTreeSet<String>,
    dependencies: &RefCell<DerivedSourceColumns>,
) -> bool {
    let optional = |node| {
        validate_optional_expression(
            node,
            source_columns,
            ctes,
            scopes,
            output_aliases,
            dependencies,
        )
    };
    let many = |nodes| {
        validate_expressions(
            nodes,
            source_columns,
            ctes,
            scopes,
            output_aliases,
            dependencies,
        )
    };
    match node.node.as_ref() {
        Some(PgNode::ColumnRef(column)) => node_strings(&column.fields).is_some_and(|names| {
            resolve_column_reference(&names, scopes, output_aliases, dependencies)
        }),
        Some(PgNode::AConst(_) | PgNode::CaseTestExpr(_)) => true,
        Some(PgNode::AExpr(expression)) => {
            optional(expression.lexpr.as_deref()) && optional(expression.rexpr.as_deref())
        }
        Some(PgNode::BoolExpr(expression)) => many(&expression.args),
        Some(PgNode::NullTest(test)) => optional(test.arg.as_deref()),
        Some(PgNode::BooleanTest(test)) => optional(test.arg.as_deref()),
        Some(PgNode::TypeCast(cast)) => optional(cast.arg.as_deref()),
        Some(PgNode::FuncCall(function)) => {
            many(&function.args)
                && many(&function.agg_order)
                && optional(function.agg_filter.as_deref())
        }
        Some(PgNode::CaseExpr(expression)) => {
            optional(expression.arg.as_deref())
                && many(&expression.args)
                && optional(expression.defresult.as_deref())
        }
        Some(PgNode::CaseWhen(when)) => {
            optional(when.expr.as_deref()) && optional(when.result.as_deref())
        }
        Some(PgNode::CoalesceExpr(expression)) => many(&expression.args),
        Some(PgNode::SubLink(link)) => {
            optional(link.testexpr.as_deref())
                && link.subselect.as_deref().is_some_and(|query| {
                    matches!(query.node.as_ref(), Some(PgNode::SelectStmt(select)) if
                    validate_select_columns(
                        select,
                        source_columns,
                        ctes,
                        scopes,
                        dependencies,
                    ))
                })
        }
        Some(PgNode::SortBy(sort)) => optional(sort.node.as_deref()),
        Some(PgNode::List(list)) => many(&list.items),
        Some(PgNode::JsonFuncExpr(function)) => {
            function.context_item.as_deref().is_none_or(|value| {
                validate_json_value_expression(
                    value,
                    source_columns,
                    ctes,
                    scopes,
                    output_aliases,
                    dependencies,
                )
            }) && optional(function.pathspec.as_deref())
                && many(&function.passing)
                && function
                    .on_empty
                    .as_deref()
                    .is_none_or(|behavior| optional(behavior.expr.as_deref()))
                && function
                    .on_error
                    .as_deref()
                    .is_none_or(|behavior| optional(behavior.expr.as_deref()))
        }
        Some(PgNode::JsonArgument(argument)) => argument.val.as_deref().is_none_or(|value| {
            validate_json_value_expression(
                value,
                source_columns,
                ctes,
                scopes,
                output_aliases,
                dependencies,
            )
        }),
        _ => false,
    }
}

fn resolve_column_reference(
    names: &[String],
    scopes: &[QueryScope],
    output_aliases: &BTreeSet<String>,
    dependencies: &RefCell<DerivedSourceColumns>,
) -> bool {
    let Some((column, qualifier)) = names.split_last() else {
        return false;
    };
    if qualifier.is_empty() {
        if output_aliases.contains(column) {
            return true;
        }
        for scope in scopes.iter().rev() {
            // A bare range name denotes its whole row. Refuse it even when a
            // column with the same name would make PostgreSQL's resolution
            // context-dependent; an author can qualify that column instead.
            if scope.qualified.contains_key(&vec![column.clone()]) {
                return false;
            }
            let matching = scope
                .relations
                .iter()
                .filter(|relation| relation.columns.contains(column))
                .collect::<Vec<_>>();
            if !matching.is_empty() {
                for relation in matching {
                    record_source_column_dependencies(
                        dependencies,
                        &relation.source_columns,
                        column,
                    );
                }
                return true;
            }
        }
        return false;
    }
    for scope in scopes.iter().rev() {
        if let Some(columns) = scope.qualified.get(qualifier) {
            let found = columns.contains(column);
            if found {
                if let Some(source_columns) = scope.qualified_source_columns.get(qualifier) {
                    record_source_column_dependencies(dependencies, source_columns, column);
                }
            }
            return found;
        }
    }
    false
}

fn record_source_column_dependencies(
    dependencies: &RefCell<DerivedSourceColumns>,
    source_columns: &DerivedSourceColumns,
    column: &str,
) {
    let mut dependencies = dependencies.borrow_mut();
    for (relation, columns) in source_columns {
        if columns.contains(column) {
            dependencies
                .entry(relation.clone())
                .or_default()
                .insert(column.to_owned());
        }
    }
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
            NodeRef::TypeCast(cast)
                if cast
                    .type_name
                    .as_ref()
                    .is_none_or(|type_name| !safe_cast_target(type_name)) =>
            {
                return false;
            }
            NodeRef::RowExpr(_) => return false,
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
    safe_scalar_type(
        type_name,
        &[
            "bool",
            "int2",
            "int4",
            "int8",
            "numeric",
            "text",
            "varchar",
            "bpchar",
            "date",
            "timestamptz",
            "uuid",
        ],
    )
}

fn safe_cast_target(type_name: &pg_query::protobuf::TypeName) -> bool {
    safe_scalar_type(
        type_name,
        &[
            "bool", "int2", "int4", "int8", "numeric", "text", "varchar", "bpchar", "date", "uuid",
            "interval",
        ],
    )
}

fn safe_scalar_type(type_name: &pg_query::protobuf::TypeName, allowed: &[&str]) -> bool {
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
    allowed.contains(&scalar)
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

    #[test]
    fn dependency_inventory_walks_nested_source_and_evaluation_nodes() {
        let dependencies = derived_sql_dependencies(
            b"WITH selected AS (SELECT m.id, registry_context.evaluation_date() AS evaluated_on FROM registry_source.member m) SELECT h.id FROM registry_source.household h LEFT JOIN selected s ON s.id = h.id",
        );

        assert_eq!(
            dependencies.source_relations,
            BTreeSet::from(["household".to_owned(), "member".to_owned()])
        );
        assert!(dependencies.uses_evaluation_date);
    }

    #[test]
    fn source_column_inventory_uses_validated_alias_and_nested_scopes() {
        let source_columns = BTreeMap::from([
            (
                "household".to_owned(),
                BTreeSet::from(["id".to_owned(), "active".to_owned(), "name".to_owned()]),
            ),
            (
                "member".to_owned(),
                BTreeSet::from(["id".to_owned(), "active".to_owned(), "name".to_owned()]),
            ),
        ]);
        let dependencies = derived_sql_source_columns(
            b"WITH selected AS (SELECT h.id AS id FROM registry_source.household h WHERE h.name IS NOT NULL) SELECT s.id, (SELECT h.active FROM registry_source.member h WHERE h.id = s.id) AS member_active FROM selected s",
            &source_columns,
        );

        assert_eq!(
            dependencies,
            BTreeMap::from([
                (
                    "household".to_owned(),
                    BTreeSet::from(["id".to_owned(), "name".to_owned()]),
                ),
                (
                    "member".to_owned(),
                    BTreeSet::from(["active".to_owned(), "id".to_owned()]),
                ),
            ])
        );
    }

    #[test]
    fn source_column_inventory_handles_join_aliases_and_lateral_correlation() {
        let source_columns = BTreeMap::from([
            (
                "household".to_owned(),
                BTreeSet::from(["id".to_owned(), "name".to_owned()]),
            ),
            (
                "member".to_owned(),
                BTreeSet::from(["active".to_owned(), "household_id".to_owned()]),
            ),
        ]);
        let joined = derived_sql_source_columns(
            b"SELECT joined.name AS name, joined.active AS active FROM (registry_source.household h JOIN registry_source.member m ON m.household_id = h.id) AS joined",
            &source_columns,
        );
        assert_eq!(
            joined,
            BTreeMap::from([
                (
                    "household".to_owned(),
                    BTreeSet::from(["id".to_owned(), "name".to_owned()]),
                ),
                (
                    "member".to_owned(),
                    BTreeSet::from(["active".to_owned(), "household_id".to_owned()]),
                ),
            ])
        );

        let lateral = derived_sql_source_columns(
            b"SELECT h.id AS id, selected.active AS active FROM registry_source.household h LEFT JOIN LATERAL (SELECT m.active AS active FROM registry_source.member m WHERE m.household_id = h.id) selected ON true",
            &source_columns,
        );
        assert_eq!(
            lateral,
            BTreeMap::from([
                ("household".to_owned(), BTreeSet::from(["id".to_owned()])),
                (
                    "member".to_owned(),
                    BTreeSet::from(["active".to_owned(), "household_id".to_owned()]),
                ),
            ])
        );
    }

    #[test]
    #[should_panic(expected = "derived SQL was validated before its dependency inventory")]
    fn dependency_inventory_refuses_sql_that_skipped_validation() {
        derived_sql_dependencies(b"SELECT FROM WHERE");
    }

    #[test]
    #[should_panic(expected = "derived SQL was validated before its dependency inventory")]
    fn dependency_inventory_refuses_non_utf8_sql() {
        derived_sql_dependencies(&[0xff, 0xfe]);
    }

    fn accepts(sql: &str) -> bool {
        let parsed = pg_query::parse(sql)
            .unwrap_or_else(|error| panic!("test SQL did not parse: {sql}: {error}"));
        let source_columns = BTreeMap::from([
            (
                "household".to_owned(),
                BTreeSet::from([
                    "id".to_owned(),
                    "active".to_owned(),
                    "amount".to_owned(),
                    "document".to_owned(),
                    "label".to_owned(),
                    "name".to_owned(),
                    "profile".to_owned(),
                ]),
            ),
            (
                "member".to_owned(),
                BTreeSet::from([
                    "id".to_owned(),
                    "active".to_owned(),
                    "document".to_owned(),
                    "valid_from".to_owned(),
                    "valid_to".to_owned(),
                ]),
            ),
        ]);
        let Some(PgNode::SelectStmt(select)) = root_node(&parsed) else {
            return false;
        };
        valid_ast(&parsed, &BTreeSet::from(["household", "member"]))
            && valid_column_references(select, &source_columns)
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
            "SELECT h.id, count(h.id)::bigint AS member_count FROM registry_source.household h GROUP BY h.id ORDER BY member_count",
            "SELECT (registry_context.evaluation_date() - INTERVAL '1 year')::date FROM registry_source.household h",
            "SELECT count(*) FILTER (WHERE m.active IS TRUE) > 0 FROM registry_source.household h LEFT JOIN registry_source.member m ON m.id = h.id GROUP BY h.id",
            "SELECT count(*) FILTER (WHERE m.valid_from <= registry_context.evaluation_date() AND (m.valid_to IS NULL OR registry_context.evaluation_date() < m.valid_to)) FROM registry_source.household h LEFT JOIN registry_source.member m ON m.id = h.id GROUP BY h.id",
        ];

        for sql in accepted {
            assert!(accepts(sql), "supported derived SELECT was refused: {sql}");
        }
    }

    #[test]
    fn casts_rows_and_attribute_notation_stay_inside_the_reviewed_scalar_surface() {
        for sql in [
            "SELECT h::text FROM registry_source.household h",
            "SELECT ROW(h.id, h.name)::text FROM registry_source.household h",
            "SELECT h.to_jsonb FROM registry_source.household h",
            "SELECT h.row_to_json FROM registry_source.household h",
            "SELECT h.quote_literal FROM registry_source.household h",
            "SELECT 'pg_catalog.pg_authid'::regclass::oid FROM registry_source.household h",
            "SELECT h.name::regclass FROM registry_source.household h",
            "SELECT 'postgres'::regrole FROM registry_source.household h",
            "SELECT h.name::xml FROM registry_source.household h",
            "SELECT h.name::text[] FROM registry_source.household h",
            "SELECT h.name::timestamptz FROM registry_source.household h",
            "SELECT h.amount::money FROM registry_source.household h",
            "SELECT JSON_VALUE(h.profile, '$.k' RETURNING regclass) FROM registry_source.household h",
        ] {
            assert!(!accepts(sql), "unsafe derived expression was accepted: {sql}");
        }

        for sql in [
            "SELECT count(h.id)::bigint FROM registry_source.household h",
            "SELECT (registry_context.evaluation_date() - INTERVAL '1 year')::date FROM registry_source.household h",
            "SELECT JSON_VALUE(h.profile, '$.at' RETURNING timestamptz) FROM registry_source.household h",
        ] {
            assert!(accepts(sql), "reviewed scalar expression was refused: {sql}");
        }
    }

    #[test]
    fn column_resolution_keeps_each_select_and_range_scope_separate() {
        let refused = [
            // The inner alias shadows the outer alias; the outer relation's
            // name column cannot validate attribute notation on the inner row.
            "SELECT (SELECT h.name FROM registry_source.member h) FROM registry_source.household h",
            // A CTE exposes only its declared output names.
            "WITH selected AS (SELECT h.id AS id FROM registry_source.household h) SELECT selected.name FROM selected",
            // A preceding CTE's output cannot validate a later CTE range.
            "WITH named AS (SELECT h.name AS name FROM registry_source.household h), selected AS (SELECT m.id AS id FROM registry_source.member m) SELECT selected.name FROM selected",
            // A scalar subquery cannot borrow a column from its sibling scalar
            // subquery, even though both appear in the same target list.
            "SELECT (SELECT h.name FROM registry_source.household h), (SELECT m.name FROM registry_source.member m) FROM registry_source.household outer_h",
            // A range name is a whole-row reference, including when another
            // visible source has a column with that name.
            "SELECT h FROM registry_source.household h JOIN registry_source.member m ON m.id = h.id",
            "SELECT DISTINCT ON (h.to_jsonb) h.id FROM registry_source.household h",
            "SELECT h.id AS h FROM registry_source.household h ORDER BY h::text",
            "SELECT h.id AS h FROM registry_source.household h GROUP BY h::text, h.id",
        ];
        for sql in refused {
            assert!(!accepts(sql), "out-of-scope column was accepted: {sql}");
        }

        let accepted = [
            "SELECT (SELECT m.id FROM registry_source.member m WHERE m.id = h.id) FROM registry_source.household h",
            "WITH named AS (SELECT h.name AS name FROM registry_source.household h), selected AS (SELECT named.name AS selected_name FROM named) SELECT selected.selected_name FROM selected",
            "SELECT nested.member_id FROM registry_source.household h JOIN LATERAL (SELECT m.id AS member_id FROM registry_source.member m WHERE m.id = h.id) nested ON true",
            "SELECT h.id AS selected_id FROM registry_source.household h ORDER BY selected_id",
            "SELECT DISTINCT ON (selected_id) h.id AS selected_id FROM registry_source.household h ORDER BY selected_id",
        ];
        for sql in accepted {
            assert!(accepts(sql), "scoped column was refused: {sql}");
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

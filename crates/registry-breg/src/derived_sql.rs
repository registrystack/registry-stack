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
    let parsed = pg_query::parse(text, 0).expect(VALIDATED);
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

/// Count how many times, up to [`SOURCE_SCANS_COUNTED`], SQL which has
/// already passed [`validate_derived_sql`] reads each `registry_source`
/// relation, counting the reads of a common table expression once for each
/// reference to it. A table expression declared inside another query is
/// counted where it is declared as well as where it is referenced, so a count
/// can be too high but never too low. Each table expression's reads are
/// counted once and added at every reference to it, so a chain of
/// expressions that each read the one before more than once takes time in
/// proportion to its length, not to the reads it makes.
pub(crate) fn derived_sql_source_scans(sql: &[u8]) -> BTreeMap<String, usize> {
    const VALIDATED: &str = "derived SQL was validated before its source scans";
    let text = std::str::from_utf8(sql).expect(VALIDATED);
    let parsed = pg_query::parse(text, 0).expect(VALIDATED);
    let Some(PgNode::SelectStmt(root)) = root_node(&parsed) else {
        panic!("{VALIDATED}");
    };
    // Validation admits only non-recursive table expressions whose names are
    // unique across the statement.
    let ctes = raw_nodes(&parsed)
        .into_iter()
        .filter_map(|node| {
            let NodeRef::CommonTableExpr(cte) = node else {
                return None;
            };
            let query = cte.ctequery.as_deref()?.node.as_ref()?;
            Some((cte.ctename.as_str(), query))
        })
        .collect::<BTreeMap<_, _>>();
    let mut main = root.clone();
    main.with_clause = None;
    let mut scans = BTreeMap::new();
    count_source_scans(
        &PgNode::SelectStmt(main),
        &ctes,
        &mut BTreeMap::new(),
        &mut scans,
    );
    scans
}

/// Where [`derived_sql_source_scans`] stops counting. Its callers only ask
/// whether SQL reads a relation more than once.
const SOURCE_SCANS_COUNTED: usize = 2;

/// Add the reads under `node` to `scans`. `expressions` holds the reads of
/// each table expression counted so far, or `None` for one still being
/// counted, and is shared by every call over one statement.
fn count_source_scans<'a>(
    node: &PgNode,
    ctes: &BTreeMap<&'a str, &'a PgNode>,
    expressions: &mut BTreeMap<&'a str, Option<BTreeMap<String, usize>>>,
    scans: &mut BTreeMap<String, usize>,
) {
    for node in raw_subtree_nodes(node) {
        let NodeRef::RangeVar(range) = node else {
            continue;
        };
        if !range.catalogname.is_empty() {
            continue;
        }
        if range.schemaname == "registry_source" {
            add_source_scans(scans, &range.relname, 1);
        } else if let Some((&name, &query)) = range
            .schemaname
            .is_empty()
            .then(|| ctes.get_key_value(range.relname.as_str()))
            .flatten()
        {
            // A non-recursive expression cannot read itself; the guard only
            // keeps a malformed reference from looping.
            if !expressions.contains_key(name) {
                expressions.insert(name, None);
                let mut reads = BTreeMap::new();
                count_source_scans(query, ctes, expressions, &mut reads);
                expressions.insert(name, Some(reads));
            }
            if let Some(Some(reads)) = expressions.get(name) {
                for (relation, count) in reads {
                    add_source_scans(scans, relation, *count);
                }
            }
        }
    }
}

fn add_source_scans(scans: &mut BTreeMap<String, usize>, relation: &str, count: usize) {
    let scans = scans.entry(relation.to_owned()).or_default();
    *scans = (*scans + count).min(SOURCE_SCANS_COUNTED);
}

/// Whether SQL which has already passed [`validate_derived_sql`] and reads
/// `relation` at most once may still give a row a value computed from other
/// rows of it. That is so unless its top-level `SELECT` reads `relation` in
/// its own `FROM` list, returns that relation's `id`, read directly, as the
/// key, and groups or picks distinct rows by nothing or by that `id`. Any
/// other key, including one read through a table expression or a subquery,
/// may name another row. An aggregate, `GROUP BY`, `HAVING` or `DISTINCT ON`
/// over anything else combines or picks among rows; one nested in a subquery
/// reads another relation, since `relation` is read once, at the top level.
pub(crate) fn derived_sql_reads_other_rows_of(sql: &[u8], relation: &str) -> bool {
    const VALIDATED: &str = "derived SQL was validated before its owner row check";
    let text = std::str::from_utf8(sql).expect(VALIDATED);
    let parsed = pg_query::parse(text, 0).expect(VALIDATED);
    let Some(PgNode::SelectStmt(root)) = root_node(&parsed) else {
        panic!("{VALIDATED}");
    };
    let reads = raw_nodes(&parsed).into_iter().any(|node| {
        matches!(
            node,
            NodeRef::RangeVar(range)
                if range.catalogname.is_empty()
                    && range.schemaname == "registry_source"
                    && range.relname == relation
        )
    });
    reads && !keeps_rows_apart(root, relation)
}

/// Whether one `SELECT` yields at most one row of `relation` per output row,
/// keyed by that row's own `id`.
fn keeps_rows_apart(select: &SelectStmt, relation: &str) -> bool {
    let Some(qualifiers) = select
        .from_clause
        .iter()
        .find_map(|node| direct_source_qualifiers(node, relation))
    else {
        return false;
    };
    // With `relation` read directly in this `FROM` list, an unqualified `id`
    // names its column, or the key in `DISTINCT ON`, unless another item has
    // an `id` too, which PostgreSQL refuses as ambiguous.
    let is_id = |node: &PgNodeWrapper| {
        matches!(
            node.node.as_ref(),
            Some(PgNode::ColumnRef(column))
                if node_strings(&column.fields).is_some_and(|fields| {
                    fields.split_last().is_some_and(|(column, qualifier)| {
                        column == "id"
                            && (qualifier.is_empty() || qualifiers.iter().any(|known| known == qualifier))
                    })
                })
        )
    };
    let key_is_id = select.target_list.first().is_some_and(|target| {
        matches!(
            target.node.as_ref(),
            Some(PgNode::ResTarget(target)) if target.val.as_deref().is_some_and(is_id)
        )
    });
    // `DISTINCT ON` keeps one row of each group it names. A plain `DISTINCT`
    // names no expression, and over rows keyed by `id` it drops none.
    let distinct_keeps_rows = select
        .distinct_clause
        .iter()
        .all(|node| node.node.is_none())
        || select.distinct_clause.iter().any(is_id);
    // `HAVING` without `GROUP BY` makes the whole statement one group.
    key_is_id
        && distinct_keeps_rows
        && if select.group_clause.is_empty() {
            select.having_clause.is_none()
        } else {
            select.group_clause.iter().any(is_id)
        }
}

/// The qualifiers of `relation` when one `FROM` item reads it directly, as a
/// table or through joins, but not inside a subquery.
fn direct_source_qualifiers(node: &PgNodeWrapper, relation: &str) -> Option<Vec<Vec<String>>> {
    match node.node.as_ref()? {
        PgNode::RangeVar(range)
            if range.catalogname.is_empty()
                && range.schemaname == "registry_source"
                && range.relname == relation =>
        {
            Some(range.alias.as_ref().map_or_else(
                || {
                    vec![
                        vec![range.relname.clone()],
                        vec![range.schemaname.clone(), range.relname.clone()],
                    ]
                },
                |alias| vec![vec![alias.aliasname.clone()]],
            ))
        }
        PgNode::JoinExpr(join) => [join.larg.as_deref(), join.rarg.as_deref()]
            .into_iter()
            .flatten()
            .find_map(|side| direct_source_qualifiers(side, relation)),
        _ => None,
    }
}

/// The `registry_source` relations that SQL which has already passed
/// [`validate_derived_sql`] reads in an expression subquery that refers to no
/// column of any query around it, directly, through a table expression, or
/// in a subquery nested in it. Such a subquery computes one value over every
/// row of those relations that the reader sees, not over the rows linked to
/// the row. A subquery resolves its columns from its own scopes first, so it
/// refers to no outer column exactly when it resolves them all with no outer
/// scope. Only the statement's top-level table expressions are taken as
/// visible to it: one declared in a nested query may refer to that query's
/// outer row, so a subquery that reads one counts as linked.
pub(crate) fn derived_sql_unlinked_reads(
    sql: &[u8],
    source_columns: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    const VALIDATED: &str = "derived SQL was validated before its unlinked reads";
    let text = std::str::from_utf8(sql).expect(VALIDATED);
    let parsed = pg_query::parse(text, 0).expect(VALIDATED);
    let Some(PgNode::SelectStmt(root)) = root_node(&parsed) else {
        panic!("{VALIDATED}");
    };
    let mut top_level = BTreeMap::new();
    for node in root.with_clause.iter().flat_map(|with| &with.ctes) {
        let Some(PgNode::CommonTableExpr(cte)) = node.node.as_ref() else {
            panic!("{VALIDATED}");
        };
        let Some(PgNode::SelectStmt(query)) = cte
            .ctequery
            .as_deref()
            .and_then(|query| query.node.as_ref())
        else {
            panic!("{VALIDATED}");
        };
        let columns = select_output_columns(query, &cte.aliascolnames).expect(VALIDATED);
        top_level.insert(cte.ctename.clone(), columns);
    }
    let ctes = raw_nodes(&parsed)
        .into_iter()
        .filter_map(|node| {
            let NodeRef::CommonTableExpr(cte) = node else {
                return None;
            };
            let query = cte.ctequery.as_deref()?.node.as_ref()?;
            Some((cte.ctename.as_str(), query))
        })
        .collect::<BTreeMap<_, _>>();
    let mut expressions = BTreeMap::new();
    let mut reads = BTreeMap::new();
    for node in raw_nodes(&parsed) {
        let NodeRef::SubLink(link) = node else {
            continue;
        };
        let Some(query @ PgNode::SelectStmt(select)) = link
            .subselect
            .as_deref()
            .and_then(|query| query.node.as_ref())
        else {
            panic!("{VALIDATED}");
        };
        if validate_select_columns(
            select,
            source_columns,
            &top_level,
            &[],
            &RefCell::new(BTreeMap::new()),
        ) {
            count_source_scans(query, &ctes, &mut expressions, &mut reads);
        }
    }
    reads.into_keys().collect()
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
    let parsed = pg_query::parse(text, 0).expect(VALIDATED);
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
    let Ok(parsed) = pg_query::parse(text, 0) else {
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
    } else if limits_returned_rows(select) {
        errors.push(Diagnostic::error(
            "breg.derived.sql-invalid",
            path,
            "derived SQL cannot apply LIMIT or OFFSET to the rows it returns, directly or through a table expression or FROM subquery, because which rows it returns would then depend on which rows the reader can see; pick among one row's linked rows in a correlated subquery instead",
        ));
    }
    refuse_encrypted_columns(&parsed, encrypted_columns, path, errors);
}

/// Whether `LIMIT` or `OFFSET` narrows the rows a `SELECT` returns, on the
/// statement itself or on a table expression or `FROM` subquery whose rows
/// feed it. Those rank across every row the caller can see. A subquery in an
/// expression, or a `LATERAL` subquery after the item it reads, runs once per
/// outer row and may narrow the rows it picks from.
fn limits_returned_rows(select: &SelectStmt) -> bool {
    select.limit_count.is_some()
        || select.limit_offset.is_some()
        || select.with_clause.as_ref().is_some_and(|with| {
            with.ctes.iter().any(|node| {
                matches!(
                    node.node.as_ref(),
                    Some(PgNode::CommonTableExpr(cte))
                        if cte.ctequery.as_deref().and_then(|query| query.node.as_ref()).is_some_and(|node| matches!(node, PgNode::SelectStmt(query) if limits_returned_rows(query)))
                )
            })
        })
        || select
            .from_clause
            .iter()
            .enumerate()
            .any(|(index, node)| from_item_limits_rows(node, index > 0))
}

fn from_item_limits_rows(node: &PgNodeWrapper, preceded: bool) -> bool {
    match node.node.as_ref() {
        Some(PgNode::RangeSubselect(range)) => !(range.lateral && preceded)
            && range
                .subquery
                .as_deref()
                .and_then(|query| query.node.as_ref())
                .is_some_and(
                    |node| matches!(node, PgNode::SelectStmt(query) if limits_returned_rows(query)),
                ),
        Some(PgNode::JoinExpr(join)) => {
            join.larg
                .as_deref()
                .is_some_and(|left| from_item_limits_rows(left, preceded))
                || join
                    .rarg
                    .as_deref()
                    .is_some_and(|right| from_item_limits_rows(right, true))
        }
        _ => false,
    }
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
                "breg.derived.sql-encrypted-column",
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
    expand_raw_nodes(
        parsed
            .protobuf
            .nodes()
            .into_iter()
            .map(|(node, _, _, _)| node)
            .collect(),
    )
}

/// [`raw_nodes`] for the tree under one node.
fn raw_subtree_nodes(node: &PgNode) -> Vec<NodeRef<'_>> {
    expand_raw_nodes(
        node.nodes()
            .into_iter()
            .map(|(node, _, _, _)| node)
            .collect(),
    )
}

fn expand_raw_nodes(mut nodes: Vec<NodeRef<'_>>) -> Vec<NodeRef<'_>> {
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
    admitted_aggregate(&name)
        || matches!(
            name.as_slice(),
            [schema, function] if schema == "registry_context" && function == "evaluation_date"
        )
}

/// The aggregate functions derived SQL may call, bare or in `pg_catalog`.
fn admitted_aggregate(name: &[String]) -> bool {
    match name {
        [function] => matches!(function.as_str(), "count" | "bool_and" | "every"),
        [schema, function] if schema == "pg_catalog" => {
            matches!(function.as_str(), "count" | "bool_and" | "every")
        }
        _ => false,
    }
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
        "breg.derived.sql-invalid",
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
    fn source_scans_count_each_read_and_each_table_expression_reference() {
        let scans = |sql: &str| {
            derived_sql_source_scans(sql.as_bytes())
                .into_iter()
                .collect::<Vec<_>>()
        };
        let counted = |pairs: &[(&str, usize)]| {
            pairs
                .iter()
                .map(|(relation, count)| ((*relation).to_owned(), *count))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            scans("SELECT h.id FROM registry_source.household h LEFT JOIN registry_source.member m ON m.household_id = h.id"),
            counted(&[("household", 1), ("member", 1)])
        );
        assert_eq!(
            scans("SELECT p.id, (SELECT count(q.id) FROM registry_source.person q WHERE q.district = p.district) AS size FROM registry_source.person p"),
            counted(&[("person", 2)])
        );
        assert_eq!(
            scans("SELECT p.id, count(q.id) FILTER (WHERE EXISTS (SELECT 1 FROM registry_source.person r WHERE r.id = q.id)) AS size FROM registry_source.person p LEFT JOIN registry_source.member q ON q.id = p.id GROUP BY p.id"),
            counted(&[("member", 1), ("person", 2)])
        );
        // An expression read once counts its reads once; read twice, twice,
        // including through another expression that reads it.
        assert_eq!(
            scans("WITH people AS (SELECT p.id AS id FROM registry_source.person p) SELECT a.id FROM people a"),
            counted(&[("person", 1)])
        );
        assert_eq!(
            scans("WITH people AS (SELECT p.id AS id, p.district AS district FROM registry_source.person p) SELECT a.id FROM people a LEFT JOIN people b ON b.district = a.district"),
            counted(&[("person", 2)])
        );
        assert_eq!(
            scans("WITH people AS (SELECT p.id AS id FROM registry_source.person p), pairs AS (SELECT a.id AS id FROM people a JOIN people b ON b.id = a.id) SELECT x.id FROM pairs x JOIN registry_source.household h ON h.id = x.id"),
            counted(&[("household", 1), ("person", 2)])
        );
        // An expression nobody references reads nothing.
        assert_eq!(
            scans("WITH unused AS (SELECT m.id AS id FROM registry_source.member m) SELECT h.id FROM registry_source.household h"),
            counted(&[("household", 1)])
        );
    }

    /// `length` table expressions `c0` to `c{length - 1}`: the first reads
    /// `registry_source.person` once, and each other one reads the one before
    /// it twice when `doubled`, or once.
    fn table_expression_chain(length: usize, doubled: bool) -> String {
        let mut ctes = vec!["c0 AS (SELECT p.id AS id FROM registry_source.person p)".to_owned()];
        for index in 1..length {
            let previous = index - 1;
            ctes.push(if doubled {
                format!("c{index} AS (SELECT a.id AS id FROM c{previous} a JOIN c{previous} b ON b.id = a.id)")
            } else {
                format!("c{index} AS (SELECT a.id AS id FROM c{previous} a)")
            });
        }
        format!("WITH {}", ctes.join(", "))
    }

    /// Run `work` on its own thread and fail the test if it has not finished
    /// within `seconds`.
    fn finishes_within<T: Send + 'static>(
        seconds: u64,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(work()));
        receiver
            .recv_timeout(std::time::Duration::from_secs(seconds))
            .unwrap_or_else(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => {
                    panic!("did not finish within {seconds} seconds")
                }
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    panic!("panicked before finishing")
                }
            })
    }

    #[test]
    fn source_scans_count_each_table_expression_once_however_often_it_is_referenced() {
        // Thirty expressions that each read the one before twice read `person`
        // 2^29 times. The count stops at two and must not expand every
        // reference to get there.
        let doubled = table_expression_chain(30, true);
        let single = table_expression_chain(30, false);
        let source_columns =
            BTreeMap::from([("person".to_owned(), BTreeSet::from(["id".to_owned()]))]);
        let (twice, once, unlinked) = finishes_within(30, move || {
            (
                derived_sql_source_scans(format!("{doubled} SELECT x.id FROM c29 x").as_bytes()),
                derived_sql_source_scans(format!("{single} SELECT x.id FROM c29 x").as_bytes()),
                derived_sql_unlinked_reads(
                    format!("{doubled} SELECT p.id AS id, (SELECT count(x.id) FROM c29 x) AS size FROM registry_source.person p").as_bytes(),
                    &source_columns,
                ),
            )
        });
        assert_eq!(twice, BTreeMap::from([("person".to_owned(), 2)]));
        assert_eq!(once, BTreeMap::from([("person".to_owned(), 1)]));
        assert_eq!(unlinked, BTreeSet::from(["person".to_owned()]));
    }

    #[test]
    fn owner_rows_stay_apart_only_under_their_own_id_read_directly() {
        let reads_other_rows =
            |sql: &str| derived_sql_reads_other_rows_of(sql.as_bytes(), "person");
        for sql in [
            "SELECT p.head AS id, count(p.id) AS size FROM registry_source.person p GROUP BY p.head",
            "SELECT p.head AS id, count(*) AS size FROM registry_source.person p GROUP BY p.head",
            "SELECT p.head AS id, pg_catalog.bool_and(p.active) AS all_active FROM registry_source.person p GROUP BY p.head",
            "SELECT p.head AS id, every(p.active) AS all_active FROM registry_source.person p GROUP BY p.head",
            "SELECT p.head AS id FROM registry_source.person p GROUP BY p.head",
            "SELECT DISTINCT p.head AS id FROM registry_source.person p",
            "SELECT DISTINCT ON (p.head) p.id AS id, true AS head FROM registry_source.person p ORDER BY p.head, p.id",
            "SELECT p.id AS id, count(p.id) AS size FROM registry_source.person p HAVING count(p.id) > 1",
            // A key other than the row's own `id` names another row, whether
            // or not anything combines rows.
            "SELECT p.head AS id, true AS head FROM registry_source.person p",
            "SELECT m.person AS id, true AS member FROM registry_source.member m JOIN registry_source.person p ON p.id = m.person",
            // So does a key read through a table expression or a subquery.
            "WITH people AS (SELECT p.id AS id, p.age AS age FROM registry_source.person p) SELECT a.id AS id, a.age AS age FROM people a",
            "SELECT s.id AS id FROM (SELECT p.id AS id FROM registry_source.person p) s",
            "WITH heads AS (SELECT p.head AS id, count(p.id) AS size FROM registry_source.person p GROUP BY p.head) SELECT h.id AS id, h.size AS size FROM heads h",
            "WITH people AS (SELECT p.head AS id FROM registry_source.person p) SELECT a.id AS id, count(*) AS size FROM people a GROUP BY a.id",
            "SELECT s.id AS id, count(m.id) AS size FROM (SELECT p.id AS id FROM registry_source.person p) s LEFT JOIN registry_source.member m ON m.person = s.id GROUP BY s.id",
        ] {
            assert!(reads_other_rows(sql), "{sql}");
        }
        for sql in [
            "SELECT p.id AS id, p.age AS age FROM registry_source.person p",
            "SELECT p.id AS id, (registry_context.evaluation_date() - p.birth_date) / 365 AS age FROM registry_source.person p",
            "SELECT id AS id, age AS age FROM registry_source.person",
            "SELECT registry_source.person.id AS id, person.age AS age FROM registry_source.person",
            "SELECT p.id AS id, m.id IS NOT NULL AS member FROM registry_source.person p LEFT JOIN registry_source.member m ON m.person = p.id",
            "SELECT p.id AS id, count(m.id) AS size FROM registry_source.person p LEFT JOIN registry_source.member m ON m.person = p.id GROUP BY p.id",
            "SELECT person.id AS id, count(m.id) AS size FROM registry_source.member m RIGHT JOIN registry_source.person ON m.person = person.id GROUP BY person.district, person.id",
            "SELECT p.id AS id, count(m.id) AS size FROM registry_source.person p LEFT JOIN registry_source.member m ON m.person = p.id GROUP BY p.id HAVING count(m.id) > 1",
            "SELECT p.id AS id, (SELECT count(m.id) FROM registry_source.member m WHERE m.person = p.id) AS size FROM registry_source.person p",
            "SELECT DISTINCT p.id AS id, p.age AS age FROM registry_source.person p",
            "SELECT DISTINCT ON (p.id) p.id AS id, m.id AS member FROM registry_source.person p LEFT JOIN registry_source.member m ON m.person = p.id ORDER BY p.id, m.id",
            "SELECT p.id AS id, (SELECT DISTINCT ON (m.person) m.id FROM registry_source.member m WHERE m.person = p.id ORDER BY m.person, m.id) AS member FROM registry_source.person p",
            // A statement that reads only another relation's rows reads none
            // of the owner's.
            "SELECT h.id AS id, count(m.id) AS size FROM registry_source.household h LEFT JOIN registry_source.member m ON m.household = h.id GROUP BY h.id",
        ] {
            assert!(!reads_other_rows(sql), "{sql}");
        }
    }

    #[test]
    fn limit_and_offset_may_narrow_only_rows_picked_per_outer_row() {
        let limits = |sql: &str| {
            let parsed = pg_query::parse(sql, 0)
                .unwrap_or_else(|error| panic!("test SQL did not parse: {sql}: {error}"));
            let Some(PgNode::SelectStmt(select)) = root_node(&parsed) else {
                panic!("not a SELECT: {sql}");
            };
            limits_returned_rows(select)
        };
        for sql in [
            "SELECT h.id FROM registry_source.household h ORDER BY h.id LIMIT 10",
            "SELECT h.id FROM registry_source.household h ORDER BY h.id OFFSET 10",
            "SELECT h.id FROM registry_source.household h ORDER BY h.id FETCH FIRST 10 ROWS ONLY",
            "WITH early AS (SELECT h.id AS id FROM registry_source.household h ORDER BY h.id LIMIT 10) SELECT e.id FROM early e",
            "WITH outer_cte AS (WITH early AS (SELECT h.id AS id FROM registry_source.household h LIMIT 10) SELECT e.id FROM early e) SELECT o.id FROM outer_cte o",
            "SELECT e.id FROM (SELECT h.id AS id FROM registry_source.household h LIMIT 10) e",
            "SELECT m.id FROM registry_source.member m JOIN (SELECT h.id AS id FROM registry_source.household h OFFSET 1) e ON e.id = m.household",
            // A `LATERAL` subquery with nothing before it reads no outer row.
            "SELECT e.id FROM LATERAL (SELECT h.id AS id FROM registry_source.household h LIMIT 10) e",
        ] {
            assert!(limits(sql), "{sql}");
        }
        for sql in [
            "SELECT h.id FROM registry_source.household h ORDER BY h.id",
            "SELECT h.id, (SELECT m.id FROM registry_source.member m WHERE m.household = h.id ORDER BY m.id LIMIT 1) FROM registry_source.household h",
            "SELECT h.id, EXISTS (SELECT 1 FROM registry_source.member m WHERE m.household = h.id OFFSET 1) FROM registry_source.household h",
            "SELECT h.id, f.id FROM registry_source.household h LEFT JOIN LATERAL (SELECT m.id AS id FROM registry_source.member m WHERE m.household = h.id ORDER BY m.id LIMIT 1) f ON true",
            "SELECT h.id, f.id FROM registry_source.household h, LATERAL (SELECT m.id AS id FROM registry_source.member m WHERE m.household = h.id LIMIT 1) f",
        ] {
            assert!(!limits(sql), "{sql}");
        }
    }

    #[test]
    fn subqueries_that_refer_to_no_outer_column_read_rows_unlinked_to_the_row() {
        let columns = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<BTreeSet<_>>()
        };
        let source_columns = BTreeMap::from([
            ("household".to_owned(), columns(&["id", "code", "district"])),
            (
                "member".to_owned(),
                columns(&["id", "household", "district"]),
            ),
            ("visit".to_owned(), columns(&["id", "member"])),
        ]);
        let unlinked = |sql: &str| {
            derived_sql_unlinked_reads(sql.as_bytes(), &source_columns)
                .into_iter()
                .collect::<Vec<_>>()
        };
        for (sql, expected) in [
            (
                "SELECT h.id AS id, (SELECT count(m.id) FROM registry_source.member m) AS size FROM registry_source.household h",
                &["member"][..],
            ),
            // Nested in a subquery linked to the row, in its `WHERE`.
            (
                "SELECT h.id AS id, (SELECT count(m.id) FROM registry_source.member m WHERE m.household = h.id AND m.id > (SELECT max(v.member) FROM registry_source.visit v)) AS size FROM registry_source.household h",
                &["visit"],
            ),
            // A subquery linked only to an unlinked one reads unlinked rows too.
            (
                "SELECT h.id AS id, (SELECT count(m.id) FROM registry_source.member m WHERE (SELECT count(v.id) FROM registry_source.visit v WHERE v.member = m.id) > 0) AS size FROM registry_source.household h",
                &["member", "visit"],
            ),
            // Through a table expression it reads.
            (
                "WITH members AS (SELECT m.id AS id FROM registry_source.member m) SELECT h.id AS id, (SELECT count(x.id) FROM members x) AS size FROM registry_source.household h",
                &["member"],
            ),
            // Inside a table expression the statement joins by the link.
            (
                "WITH counted AS (SELECT m.household AS household, (SELECT count(v.id) FROM registry_source.visit v) AS visits FROM registry_source.member m) SELECT h.id AS id, c.visits AS visits FROM registry_source.household h JOIN counted c ON c.household = h.id",
                &["visit"],
            ),
            (
                "SELECT h.id AS id, (SELECT count(m.id) FROM registry_source.member m WHERE m.household = h.id) AS size FROM registry_source.household h",
                &[],
            ),
            // An unqualified column only the outer row has refers to it.
            (
                "SELECT h.id AS id, (SELECT count(m.id) FROM registry_source.member m WHERE m.district = code) AS size FROM registry_source.household h",
                &[],
            ),
            (
                "SELECT h.id AS id, count(m.id) AS size FROM registry_source.household h LEFT JOIN registry_source.member m ON m.household = h.id GROUP BY h.id",
                &[],
            ),
        ] {
            assert_eq!(unlinked(sql), expected, "{sql}");
        }
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
        let parsed = pg_query::parse(sql, 0)
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
            let parsed = pg_query::parse(sql, 0).expect("test SQL parses");
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
                    .any(|diagnostic| diagnostic.code == "breg.derived.sql-encrypted-column"),
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

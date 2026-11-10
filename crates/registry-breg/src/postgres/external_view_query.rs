// SPDX-License-Identifier: Apache-2.0
//! Indexed external views over the selected profile's ordinary root RLS.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;
use tokio_postgres::types::Type;
use uuid::Uuid;

use crate::contract::Operation;
use crate::external_views::{ExternalCardinality, ExternalFieldType, ExternalProjectionMode};
use crate::model::CompiledRegistry;

use super::external_projection::{ProjectionGeneration, ProjectionScope};
use super::read::ReadRelations;
use super::GuardedTransaction;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ExternalQueryError {
    #[error("external view is unavailable")]
    Unavailable,
    #[error("external view query is not permitted")]
    NotPermitted,
    #[error("external view query is invalid")]
    InvalidQuery,
    #[error("external view generation changed; restart the query")]
    GenerationChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SortDirection {
    Ascending,
    Descending,
}

impl SortDirection {
    fn sql(self) -> &'static str {
        match self {
            Self::Ascending => "ASC",
            Self::Descending => "DESC",
        }
    }
    fn comparison(self) -> &'static str {
        match self {
            Self::Ascending => ">",
            Self::Descending => "<",
        }
    }
}

pub(crate) struct ExactFilter {
    pub(crate) field: String,
    pub(crate) value: Value,
}

pub(crate) struct ExternalOrder {
    pub(crate) field: String,
    pub(crate) direction: SortDirection,
}

/// Internal cursor material. The source key and sort value must only leave
/// BReg inside its encrypted, caller/query/generation-bound cursor.
pub(crate) struct PageAfter {
    pub(crate) root_id: Uuid,
    pub(crate) source_key: String,
    pub(crate) sort_value: Option<String>,
}

impl fmt::Debug for PageAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PageAfter(<redacted>)")
    }
}

pub(crate) struct LabelScope<'a> {
    pub(crate) scope: &'a ProjectionScope,
    pub(crate) generation: ProjectionGeneration,
}

pub(crate) struct IndexedViewQuery<'a> {
    pub(crate) profile_id: &'a str,
    pub(crate) view_id: &'a str,
    pub(crate) link_id: &'a str,
    pub(crate) scope: &'a ProjectionScope,
    /// Obtained with `lock_generation` in this same transaction.
    pub(crate) generation: ProjectionGeneration,
    pub(crate) label_scope: Option<LabelScope<'a>>,
    pub(crate) now: i64,
    pub(crate) root_id: Option<Uuid>,
    pub(crate) fields: BTreeSet<String>,
    pub(crate) filter: Option<ExactFilter>,
    pub(crate) order: Option<ExternalOrder>,
    pub(crate) include_count: bool,
    pub(crate) page_size: u16,
    pub(crate) after: Option<PageAfter>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExternalAvailability {
    Available,
    Absent,
    Unavailable,
}

#[derive(Deserialize)]
pub(crate) struct ExternalLabel {
    pub(crate) availability: ExternalAvailability,
    pub(crate) fields: Value,
}

#[derive(Deserialize)]
pub(crate) struct ExternalViewRow {
    pub(crate) root_id: Uuid,
    /// Internal stable row identity, not an automatically disclosed field.
    pub(crate) source_key: String,
    pub(crate) availability: ExternalAvailability,
    pub(crate) fields: Value,
    pub(crate) label: Option<ExternalLabel>,
    sort_value: Option<String>,
}

impl fmt::Debug for ExternalViewRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalViewRow(<redacted>)")
    }
}

pub(crate) struct IndexedViewPage {
    pub(crate) complete: bool,
    /// A requested local root outside the selected profile remains concealed.
    pub(crate) root_found: bool,
    pub(crate) rows: Vec<ExternalViewRow>,
    pub(crate) total_count: Option<u64>,
    pub(crate) continuation: Option<PageAfter>,
    /// Recheck this bound after terminal audit and before releasing values.
    pub(crate) minimum_expires_at: Option<i64>,
}

/// Root authority is installed by `begin_record_transaction`. This function
/// rechecks all named view and query grants, and derives relations solely from
/// the compiled root inventory. It never accepts raw SQL or a source key.
pub(crate) async fn query(
    transaction: &GuardedTransaction<'_>,
    registry: &CompiledRegistry,
    request: IndexedViewQuery<'_>,
) -> Result<IndexedViewPage, ExternalQueryError> {
    let statement = compile(registry, &request)?;
    let parameters = statement
        .parameters
        .iter()
        .map(|value| {
            (
                value as &(dyn tokio_postgres::types::ToSql + Sync),
                Type::TEXT,
            )
        })
        .collect::<Vec<_>>();
    let row = transaction
        .transaction()
        .query_typed_one(&statement.sql, &parameters)
        .await
        .map_err(|_| ExternalQueryError::Unavailable)?;
    if !row.get::<_, bool>(0) {
        return Err(ExternalQueryError::GenerationChanged);
    }
    let complete: bool = row.get(1);
    let root_found: bool = row.get(2);
    let minimum_expires_at = row.get(3);
    let count: Option<i64> = row.get(4);
    let mut rows: Vec<ExternalViewRow> =
        serde_json::from_value(row.get(5)).map_err(|_| ExternalQueryError::Unavailable)?;
    let has_more = rows.len() > usize::from(request.page_size);
    rows.truncate(usize::from(request.page_size));
    let continuation = if has_more {
        rows.last().map(|row| PageAfter {
            root_id: row.root_id,
            source_key: row.source_key.clone(),
            sort_value: row.sort_value.clone(),
        })
    } else {
        None
    };
    Ok(IndexedViewPage {
        complete,
        root_found,
        rows,
        total_count: count
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ExternalQueryError::Unavailable)?,
        continuation,
        minimum_expires_at,
    })
}

struct QueryStatement {
    sql: String,
    parameters: Vec<Option<String>>,
}

fn compile(
    registry: &CompiledRegistry,
    request: &IndexedViewQuery<'_>,
) -> Result<QueryStatement, ExternalQueryError> {
    if !(1..=1000).contains(&request.page_size) || request.now < 0 {
        return Err(ExternalQueryError::InvalidQuery);
    }
    let inventory = registry.external_views();
    let view = inventory
        .views
        .get(request.view_id)
        .ok_or(ExternalQueryError::NotPermitted)?;
    let link = view
        .links
        .iter()
        .find(|link| link.id.as_str() == request.link_id)
        .ok_or(ExternalQueryError::NotPermitted)?;
    let grant = inventory
        .grants
        .get(request.profile_id)
        .and_then(|grants| grants.get(request.view_id))
        .and_then(|grant| {
            grant
                .links
                .iter()
                .find(|grant| grant.link.as_str() == request.link_id)
        })
        .ok_or(ExternalQueryError::NotPermitted)?;
    let projection = inventory
        .projections
        .get(link.projection.as_str())
        .ok_or(ExternalQueryError::NotPermitted)?;
    let external_type = inventory
        .record_types
        .get(projection.record_type.as_str())
        .ok_or(ExternalQueryError::NotPermitted)?;
    let entity = registry
        .entities()
        .get(view.record_type.as_str())
        .ok_or(ExternalQueryError::NotPermitted)?;
    let profile = entity
        .access_profiles
        .get(request.profile_id)
        .ok_or(ExternalQueryError::NotPermitted)?;
    let operation = if request.root_id.is_some() {
        Operation::Get
    } else {
        Operation::List
    };
    if !profile.operations.contains(&operation)
        || projection.mode != ExternalProjectionMode::Indexed
        || request.scope.projection_id != projection.id.as_str()
        || request.generation.epoch != request.scope.epoch
        || (projection.cardinality == ExternalCardinality::Many && request.root_id.is_none())
        || request.fields.iter().any(|field| {
            !grant
                .readable_fields
                .iter()
                .any(|allowed| allowed.as_str() == field)
        })
        || (request.include_count && !grant.allow_count)
    {
        return Err(ExternalQueryError::NotPermitted);
    }
    let field_types = external_type
        .fields
        .iter()
        .map(|field| (field.id.to_string(), field.value_type))
        .collect::<BTreeMap<_, _>>();
    if let Some(filter) = &request.filter {
        if !grant
            .filterable_fields
            .iter()
            .any(|field| field.as_str() == filter.field)
            || !grant
                .readable_fields
                .iter()
                .any(|field| field.as_str() == filter.field)
        {
            return Err(ExternalQueryError::NotPermitted);
        }
    }
    if let Some(order) = &request.order {
        if !grant
            .sortable_fields
            .iter()
            .any(|field| field.as_str() == order.field)
            || !grant
                .readable_fields
                .iter()
                .any(|field| field.as_str() == order.field)
        {
            return Err(ExternalQueryError::NotPermitted);
        }
    }
    let key_field = link.from_field.as_str();
    if key_field != "id"
        && !entity
            .stored_fields
            .iter()
            .any(|field| field.logical.id == key_field)
    {
        return Err(ExternalQueryError::InvalidQuery);
    }
    let relations = ReadRelations::statistics(entity, &[key_field.to_owned()])
        .map_err(|_| ExternalQueryError::Unavailable)?;
    let key = relations
        .field_expression(entity, key_field)
        .map_err(|_| ExternalQueryError::Unavailable)?;
    if key.encrypted {
        return Err(ExternalQueryError::NotPermitted);
    }
    let mut parameters = vec![];
    let profile_param = parameter(&mut parameters, Some(request.profile_id.to_owned()));
    let root_param = parameter(&mut parameters, request.root_id.map(|id| id.to_string()));
    let now = parameter(&mut parameters, Some(request.now.to_string()));
    let scope = scope_predicate("s", request.scope, request.generation, &mut parameters);
    // Root fields carry the generated text collation. Reading the link key in
    // the snapshot and value keys' own collation lets their primary keys serve
    // the lookup for each root; both collations are deterministic, so
    // equality is unchanged.
    // A link key the write path would refuse reads as no outside value, like
    // an empty one.
    let subject_key = crate::external_views::acceptable_link_key_sql("raw_key");
    let root_sql = format!("SELECT root_id,{subject_key} AS subject_key FROM (SELECT {} AS root_id,({})::text COLLATE \"default\" AS raw_key FROM {} WHERE current_setting('registry.access_profile',true)={profile_param} AND ({root_param}::uuid IS NULL OR {}={root_param}::uuid)) AS linked",relations.id_expression,key.sql,relations.from_sql,relations.id_expression);
    let many = projection.cardinality == ExternalCardinality::Many;
    let expected_kind = if many {
        "o.kind='complete-collection'"
    } else {
        "o.kind IN ('one','absent')"
    };
    let selected = project_fields("data", &request.fields);
    let filter = if let Some(filter) = &request.filter {
        let kind = *field_types
            .get(&filter.field)
            .ok_or(ExternalQueryError::InvalidQuery)?;
        let expression = field_expression("data", &filter.field, kind);
        match scalar(&filter.value, kind)? {
            None => format!("{expression} IS NULL"),
            Some(value) => format!(
                "{expression}={}::{}",
                parameter(&mut parameters, Some(value)),
                sql_type(kind)
            ),
        }
    } else {
        "true".to_owned()
    };
    let order_type = request
        .order
        .as_ref()
        .map(|order| {
            field_types
                .get(&order.field)
                .copied()
                .ok_or(ExternalQueryError::InvalidQuery)
        })
        .transpose()?;
    let sort_expression = match (&request.order, order_type) {
        (Some(order), Some(kind)) => field_expression("data", &order.field, kind),
        _ => "NULL::text".to_owned(),
    };
    // A date's text output follows the session's DateStyle. The cursor
    // carries ISO 8601, which the continuation parses under any style.
    let sort_value = if order_type == Some(ExternalFieldType::Date) {
        "to_char(matched.sort_key,'YYYY-MM-DD')"
    } else {
        "matched.sort_key::text"
    };
    let direction = request
        .order
        .as_ref()
        .map_or(SortDirection::Ascending, |order| order.direction);
    let order_sql = if request.order.is_some() {
        format!(
            "sort_key {} NULLS LAST,root_id ASC,source_key COLLATE \"C\" ASC",
            direction.sql()
        )
    } else {
        "root_id ASC,source_key COLLATE \"C\" ASC".to_owned()
    };
    let after = continuation_sql(
        request
            .after
            .as_ref()
            .map(|after| (after, order_type.map(|kind| ("sort_key", kind, direction)))),
        &mut parameters,
    )?;
    let require_complete =
        request.filter.is_some() || request.order.is_some() || request.include_count || many;
    let limit = parameter(
        &mut parameters,
        Some((u32::from(request.page_size) + 1).to_string()),
    );
    let count = if request.include_count {
        "CASE WHEN coverage.complete THEN (SELECT count(*) FROM filtered) ELSE NULL END"
    } else {
        "NULL::bigint"
    };

    let (label_state, label_join, label_value, label_valid, label_expiry) = if let Some(
        label_scope,
    ) =
        &request.label_scope
    {
        let label = link
            .label
            .as_ref()
            .ok_or(ExternalQueryError::NotPermitted)?;
        if grant.label_fields.is_empty()
            || label_scope.scope.projection_id != label.projection.as_str()
            || label_scope.generation.epoch != label_scope.scope.epoch
        {
            return Err(ExternalQueryError::NotPermitted);
        }
        let label_projection = inventory
            .projections
            .get(label.projection.as_str())
            .ok_or(ExternalQueryError::NotPermitted)?;
        if label_projection.mode != ExternalProjectionMode::Indexed
            || label_projection.cardinality != ExternalCardinality::One
        {
            return Err(ExternalQueryError::NotPermitted);
        }
        let predicate = scope_predicate(
            "s",
            label_scope.scope,
            label_scope.generation,
            &mut parameters,
        );
        let label_fields = grant.label_fields.iter().map(ToString::to_string).collect();
        let from = literal(label.from_field.as_str());
        (
            format!(",label_state AS MATERIALIZED (SELECT * FROM registry_internal.registry_external_projection_scopes AS s WHERE {predicate})"),
            format!("LEFT JOIN label_state AS ls ON true LEFT JOIN registry_internal.registry_external_projection_snapshots AS lo ON lo.projection_id=ls.projection_id AND lo.epoch=ls.epoch AND lo.subject_key=matched.data->>{from} AND lo.expires_at>{now}::bigint AND lo.kind IN ('one','absent') LEFT JOIN registry_internal.registry_external_projection_values AS lv ON lv.projection_id=lo.projection_id AND lv.epoch=lo.epoch AND lv.subject_key=lo.subject_key AND lv.source_key=lo.subject_key"),
            format!("CASE WHEN matched.data->>{from} IS NULL THEN NULL::jsonb ELSE jsonb_build_object('availability',CASE WHEN lo.kind='one' THEN 'available' WHEN lo.kind='absent' THEN 'absent' ELSE 'unavailable' END,'fields',{}) END",project_fields("lv.fields",&label_fields)),
            String::new(),
            "lo.expires_at".to_owned(),
        )
    } else {
        let label_value = match &link.label {
            Some(label) if !grant.label_fields.is_empty() => {
                let from = literal(label.from_field.as_str());
                let fields = grant.label_fields.iter().map(ToString::to_string).collect();
                format!("CASE WHEN matched.data->>{from} IS NULL THEN NULL::jsonb ELSE jsonb_build_object('availability','unavailable','fields',{}) END",project_fields("NULL::jsonb",&fields))
            }
            _ => "NULL::jsonb".to_owned(),
        };
        (
            String::new(),
            String::new(),
            label_value,
            String::new(),
            "NULL::bigint".to_owned(),
        )
    };
    let membership = if many {
        "JOIN registry_internal.registry_external_projection_values AS v ON v.projection_id=c.projection_id AND v.epoch=c.epoch AND v.subject_key=c.subject_key WHERE c.covered"
    } else {
        "LEFT JOIN registry_internal.registry_external_projection_values AS v ON v.projection_id=c.projection_id AND v.epoch=c.epoch AND v.subject_key=c.subject_key AND v.source_key=c.subject_key AND c.covered"
    };
    let sql = format!(
        r#"WITH projection_state AS MATERIALIZED (
            SELECT * FROM registry_internal.registry_external_projection_scopes AS s WHERE {scope}
        ){label_state}, authorized_roots AS MATERIALIZED ({root_sql}),
        candidates AS MATERIALIZED (
            SELECT r.root_id,r.subject_key,s.projection_id,s.epoch,o.kind,o.expires_at,
                (COALESCE(r.subject_key,'')='' OR COALESCE(o.expires_at>{now}::bigint AND {expected_kind},false)) AS covered
            FROM authorized_roots AS r LEFT JOIN projection_state AS s ON true
            LEFT JOIN registry_internal.registry_external_projection_snapshots AS o
                ON o.projection_id=s.projection_id AND o.epoch=s.epoch AND o.subject_key=r.subject_key
        ), coverage AS MATERIALIZED (
            SELECT COALESCE(bool_and(covered),true) AND EXISTS (SELECT 1 FROM projection_state) AS complete,
                count(*)>0 AS root_found,min(expires_at) FILTER (WHERE covered) AS expires_at FROM candidates
        ), matched AS MATERIALIZED (
            SELECT c.root_id,COALESCE(v.source_key,'') AS source_key,
                CASE WHEN c.covered AND (COALESCE(c.subject_key,'')='' OR c.kind='absent') THEN 'absent' WHEN c.covered THEN 'available' ELSE 'unavailable' END AS availability,
                CASE WHEN c.covered THEN v.fields ELSE NULL::jsonb END AS data
            FROM candidates AS c {membership}
        ), filtered AS MATERIALIZED (
            SELECT *,{sort_expression} AS sort_key FROM matched WHERE {filter}
        ), page AS MATERIALIZED (
            SELECT *,row_number() OVER (ORDER BY {order_sql}) AS ordinal
            FROM filtered WHERE {after} AND (NOT {require_complete} OR (SELECT complete FROM coverage))
            ORDER BY {order_sql} LIMIT {limit}::bigint
        ), displayed AS (
            SELECT matched.ordinal,{label_expiry} AS label_expires_at,
                jsonb_build_object('root_id',matched.root_id,'source_key',matched.source_key,
                    'availability',matched.availability,'fields',{selected},'label',{label_value},'sort_value',{sort_value}) AS payload
            FROM page AS matched {label_join}
        ) SELECT EXISTS (SELECT 1 FROM projection_state){label_valid},coverage.complete,coverage.root_found,
            LEAST(coverage.expires_at,(SELECT min(label_expires_at) FROM displayed)),{count},
            COALESCE((SELECT jsonb_agg(payload ORDER BY ordinal) FROM displayed),'[]'::jsonb)
        FROM coverage"#
    );
    Ok(QueryStatement { sql, parameters })
}

fn parameter(parameters: &mut Vec<Option<String>>, value: Option<String>) -> String {
    parameters.push(value);
    format!("${}::text", parameters.len())
}

fn scope_predicate(
    alias: &str,
    scope: &ProjectionScope,
    generation: ProjectionGeneration,
    parameters: &mut Vec<Option<String>>,
) -> String {
    let id = parameter(parameters, Some(scope.projection_id.clone()));
    let epoch = parameter(parameters, Some(scope.epoch.to_string()));
    let binding = parameter(parameters, Some(scope.binding_digest.clone()));
    let grant = parameter(parameters, Some(scope.grant_digest.clone()));
    let version = parameter(parameters, Some(generation.generation.to_string()));
    format!("{alias}.projection_id={id} AND {alias}.epoch={epoch}::uuid AND {alias}.binding_digest={binding} AND {alias}.grant_digest={grant} AND {alias}.generation={version}::bigint AND {alias}.active")
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn project_fields(alias: &str, fields: &BTreeSet<String>) -> String {
    if fields.is_empty() {
        return "'{}'::jsonb".to_owned();
    }
    let fields = fields
        .iter()
        .map(|field| format!("{},({alias})->{}", literal(field), literal(field)))
        .collect::<Vec<_>>()
        .join(",");
    format!("CASE WHEN ({alias}) IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object({fields}) END")
}

fn field_expression(alias: &str, field: &str, kind: ExternalFieldType) -> String {
    let cast = sql_type(kind);
    let expression = format!("(({alias})->>{})::{cast}", literal(field));
    if kind == ExternalFieldType::String {
        format!("({expression}) COLLATE \"C\"")
    } else {
        expression
    }
}

fn sql_type(kind: ExternalFieldType) -> &'static str {
    match kind {
        ExternalFieldType::String => "text",
        ExternalFieldType::Integer => "bigint",
        ExternalFieldType::Boolean => "boolean",
        ExternalFieldType::Decimal => "numeric",
        ExternalFieldType::Date => "date",
        ExternalFieldType::Uuid => "uuid",
    }
}

/// Largest string a request filter may carry.
const MAXIMUM_FILTER_STRING_BYTES: usize = 4096;
/// Largest sort value a continuation resumes from. Only a cursor BReg sealed
/// carries one, and the cursor's own payload bound (8 KiB, shared with the
/// request's key, query and binding) is the effective limit above this.
pub(crate) const MAXIMUM_CURSOR_SORT_VALUE_BYTES: usize = 6144;

/// Whether a continuation may resume from `value`. The server applies it when
/// it issues a cursor and again when it opens one, so a cursor it issues is
/// always one it accepts.
pub(crate) fn sort_value_resumable(value: &str) -> bool {
    value.len() <= MAXIMUM_CURSOR_SORT_VALUE_BYTES
}

fn scalar(value: &Value, kind: ExternalFieldType) -> Result<Option<String>, ExternalQueryError> {
    bounded_scalar(value, kind, MAXIMUM_FILTER_STRING_BYTES)
}

fn bounded_scalar(
    value: &Value,
    kind: ExternalFieldType,
    maximum_string_bytes: usize,
) -> Result<Option<String>, ExternalQueryError> {
    if value.is_null() {
        return Ok(None);
    }
    let invalid = || ExternalQueryError::InvalidQuery;
    let result = match kind {
        ExternalFieldType::String => value
            .as_str()
            .filter(|s| s.len() <= maximum_string_bytes)
            .map(str::to_owned)
            .ok_or_else(invalid)?,
        ExternalFieldType::Integer => value.as_i64().map(|v| v.to_string()).ok_or_else(invalid)?,
        ExternalFieldType::Boolean => value.as_bool().map(|v| v.to_string()).ok_or_else(invalid)?,
        ExternalFieldType::Decimal => {
            let value = value.as_str().ok_or_else(invalid)?;
            let digits = value.strip_prefix('-').unwrap_or(value);
            let mut parts = digits.split('.');
            let integer = parts.next().unwrap_or("");
            let fraction = parts.next();
            if value.len() > 128
                || integer.is_empty()
                || !integer.bytes().all(|b| b.is_ascii_digit())
                || fraction.is_some_and(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
                || parts.next().is_some()
            {
                return Err(invalid());
            }
            value.to_owned()
        }
        ExternalFieldType::Date => {
            let value = value.as_str().ok_or_else(invalid)?;
            if value.len() != 10 || chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_err() {
                return Err(invalid());
            }
            value.to_owned()
        }
        ExternalFieldType::Uuid => Uuid::parse_str(value.as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .to_string(),
    };
    Ok(Some(result))
}

type ContinuationOrder<'a> = Option<(&'a str, ExternalFieldType, SortDirection)>;

fn continuation_sql(
    after: Option<(&PageAfter, ContinuationOrder<'_>)>,
    parameters: &mut Vec<Option<String>>,
) -> Result<String, ExternalQueryError> {
    let Some((after, order)) = after else {
        return Ok("true".to_owned());
    };
    if after.source_key.len() > 1024 {
        return Err(ExternalQueryError::InvalidQuery);
    }
    let root = parameter(parameters, Some(after.root_id.to_string()));
    let key = parameter(parameters, Some(after.source_key.clone()));
    let tie = format!("(root_id,source_key COLLATE \"C\")>({root}::uuid,{key} COLLATE \"C\")");
    let Some((column, kind, direction)) = order else {
        if after.sort_value.is_some() {
            return Err(ExternalQueryError::InvalidQuery);
        }
        return Ok(tie);
    };
    match &after.sort_value {
        None => Ok(format!("{column} IS NULL AND {tie}")),
        Some(value) => {
            if !sort_value_resumable(value) {
                return Err(ExternalQueryError::InvalidQuery);
            }
            let parsed = match kind {
                ExternalFieldType::Integer => value
                    .parse::<i64>()
                    .map(Value::from)
                    .map_err(|_| ExternalQueryError::InvalidQuery)?,
                ExternalFieldType::Boolean => value
                    .parse::<bool>()
                    .map(Value::from)
                    .map_err(|_| ExternalQueryError::InvalidQuery)?,
                _ => Value::String(value.clone()),
            };
            let value = bounded_scalar(&parsed, kind, MAXIMUM_CURSOR_SORT_VALUE_BYTES)?
                .ok_or(ExternalQueryError::InvalidQuery)?;
            let value = parameter(parameters, Some(value));
            let cast = sql_type(kind);
            Ok(format!("({column} {} {value}::{cast} OR {column} IS NULL OR ({column}={value}::{cast} AND {tie}))",direction.comparison()))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn registry() -> CompiledRegistry {
        registry_with_external(true)
    }

    pub(crate) fn registry_with_external(include_external: bool) -> CompiledRegistry {
        let mut project = project();
        if !include_external {
            let root = project.as_object_mut().unwrap();
            root.remove("externalRecordTypes");
            root.remove("externalProjections");
            root.remove("externalViews");
            root.get_mut("accessProfiles")
                .unwrap()
                .as_array_mut()
                .unwrap()[0]["permissions"]
                .as_object_mut()
                .unwrap()
                .remove("externalViews");
        }
        compile_project(&project)
    }

    /// The authoring project behind [`registry`], for tests that edit it.
    pub(crate) fn project() -> Value {
        json!({
            "apiVersion":crate::compiler::AUTHORING_API_VERSION,"kind":"BRegProject",
            "project":{"id":"external-query-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://fixture.example.test"},
            "datasets":[{"id":"records"}],
            "recordTypes":[{"id":"local-record","primaryDataset":"records","route":"records","mutationMode":"mutable","classification":"internal","fields":[
                {"id":"subject-key","type":"string","maximumLength":64,"classification":"internal"},
                {"id":"tenant","type":"string","maximumLength":32,"classification":"internal"}
            ]}],
            "externalRecordTypes":[{"id":"external-record","authority":"urn:test:authority","identifierScheme":"urn:test:keys","fields":[
                {"id":"label","type":"string","classification":"internal"},
                {"id":"hidden","type":"string","classification":"restricted"}
            ]}],
            "externalProjections":[{"id":"projection","recordType":"external-record","operation":"batch","operationVersion":"1","purpose":"consultation","scope":"eligible","selectorScheme":"urn:test:keys","mode":"indexed","cardinality":"one","cacheTtlSeconds":60,"fields":["label","hidden"]}],
            "externalViews":[{"id":"view","recordType":"local-record","links":[{"id":"link","projection":"projection","fromField":"subject-key","identifierScheme":"urn:test:keys","fields":["label","hidden"]}]}],
            "accessProfiles":[{"id":"reader","principalClaim":"registry_principal","requiredScopes":["registry.read"],"requiredPurposes":["consultation"],"permissions":{
                "records":[{"recordType":"local-record","operations":["get","list"],"allowCount":true,"rowBoundaries":[{"field":"tenant","claim":"tenant","operator":"equals"}]}],
                "externalViews":[{"view":"view","links":[{"link":"link","readableFields":["label"],"filterableFields":["label"],"sortableFields":["label"],"allowCount":true}]}]
            }}]
        })
    }

    pub(crate) fn compile_project(project: &Value) -> CompiledRegistry {
        let project =
            crate::contract::parse_project_json(&serde_json::to_vec(project).unwrap()).unwrap();
        crate::compiler::compile_project(&project, &[], crate::compiler::CompileProfile::Authoring)
            .unwrap()
    }

    pub(super) fn request(scope: &ProjectionScope, generation: i64) -> IndexedViewQuery<'_> {
        IndexedViewQuery {
            profile_id: "reader",
            view_id: "view",
            link_id: "link",
            scope,
            generation: ProjectionGeneration {
                epoch: scope.epoch,
                generation,
            },
            label_scope: None,
            now: 1000,
            root_id: None,
            fields: BTreeSet::from(["label".to_owned()]),
            filter: None,
            order: None,
            include_count: false,
            page_size: 10,
            after: None,
        }
    }

    #[test]
    fn query_kernel_refuses_hidden_fields_in_selection_filter_and_order() {
        let registry = registry();
        let scope =
            ProjectionScope::new("projection", Uuid::new_v4(), "binding", "grant", 60).unwrap();
        let mut query = request(&scope, 0);
        query.fields = BTreeSet::from(["hidden".to_owned()]);
        assert!(matches!(
            compile(&registry, &query),
            Err(ExternalQueryError::NotPermitted)
        ));
        query.fields = BTreeSet::from(["label".to_owned()]);
        query.filter = Some(ExactFilter {
            field: "hidden".to_owned(),
            value: json!("secret"),
        });
        assert!(matches!(
            compile(&registry, &query),
            Err(ExternalQueryError::NotPermitted)
        ));
        query.filter = None;
        query.order = Some(ExternalOrder {
            field: "hidden".to_owned(),
            direction: SortDirection::Ascending,
        });
        assert!(matches!(
            compile(&registry, &query),
            Err(ExternalQueryError::NotPermitted)
        ));
    }

    #[test]
    fn exact_values_are_typed_and_null_keeps_native_missing_semantics() {
        assert_eq!(
            scalar(&json!(null), ExternalFieldType::String).unwrap(),
            None
        );
        assert_eq!(
            scalar(&json!(12), ExternalFieldType::Integer).unwrap(),
            Some("12".into())
        );
        assert!(scalar(&json!("12"), ExternalFieldType::Integer).is_err());
        assert!(scalar(&json!("2024-02-30"), ExternalFieldType::Date).is_err());
        assert!(scalar(&json!("0; SELECT 1"), ExternalFieldType::Decimal).is_err());
        assert_eq!(
            scalar(&json!("-12.50"), ExternalFieldType::Decimal).unwrap(),
            Some("-12.50".into())
        );
    }

    #[test]
    fn a_sort_value_past_the_filter_bound_resumes_within_the_cursor_bound() {
        let order = |value: String| {
            let after = PageAfter {
                root_id: Uuid::nil(),
                source_key: "row".into(),
                sort_value: Some(value),
            };
            let mut params = vec![];
            continuation_sql(
                Some((
                    &after,
                    Some((
                        "sort_key",
                        ExternalFieldType::String,
                        SortDirection::Ascending,
                    )),
                )),
                &mut params,
            )
        };
        assert!(order("a".repeat(5000)).is_ok());
        assert!(order("a".repeat(MAXIMUM_CURSOR_SORT_VALUE_BYTES)).is_ok());
        assert!(matches!(
            order("a".repeat(MAXIMUM_CURSOR_SORT_VALUE_BYTES + 1)),
            Err(ExternalQueryError::InvalidQuery)
        ));
        // A request filter keeps its own, smaller bound.
        assert!(scalar(&json!("a".repeat(5000)), ExternalFieldType::String).is_err());
    }

    #[test]
    fn a_continuation_preserves_nulls_last_in_both_directions() {
        let after = PageAfter {
            root_id: Uuid::nil(),
            source_key: "row".into(),
            sort_value: Some("x".into()),
        };
        let mut params = vec![];
        let asc = continuation_sql(
            Some((
                &after,
                Some((
                    "sort_key",
                    ExternalFieldType::String,
                    SortDirection::Ascending,
                )),
            )),
            &mut params,
        )
        .unwrap();
        assert!(asc.contains("sort_key >"));
        assert!(asc.contains("sort_key IS NULL"));
        let desc = continuation_sql(
            Some((
                &after,
                Some((
                    "sort_key",
                    ExternalFieldType::String,
                    SortDirection::Descending,
                )),
            )),
            &mut params,
        )
        .unwrap();
        assert!(desc.contains("sort_key <"));
        assert!(desc.contains("sort_key IS NULL"));
    }
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod postgres_tests {
    use super::super::external_projection::{configure_scope, install, INSTALL_SQL};
    use super::*;
    use std::time::Duration;
    use tokio_postgres::{Client, NoTls};

    #[allow(dead_code)]
    mod harness {
        use crate as registry_breg;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/postgres_harness.rs"
        ));
    }

    async fn run(
        client: &Client,
        registry: &CompiledRegistry,
        request: &IndexedViewQuery<'_>,
    ) -> tokio_postgres::Row {
        run_statement(client, &compile(registry, request).unwrap()).await
    }

    async fn run_statement(client: &Client, statement: &QueryStatement) -> tokio_postgres::Row {
        let parameters = statement
            .parameters
            .iter()
            .map(|value| {
                (
                    value as &(dyn tokio_postgres::types::ToSql + Sync),
                    Type::TEXT,
                )
            })
            .collect::<Vec<_>>();
        client
            .query_typed_one(&statement.sql, &parameters)
            .await
            .expect("compiled external SQL executes")
    }

    async fn publish(
        client: &Client,
        scope: &ProjectionScope,
        key: &str,
        label: Option<&str>,
        id: &str,
    ) {
        let fields = label.map(|label| serde_json::json!({"label": label}));
        publish_fields(client, scope, key, fields, id).await;
    }

    async fn publish_fields(
        client: &Client,
        scope: &ProjectionScope,
        key: &str,
        fields: Option<Value>,
        id: &str,
    ) {
        let sequence = allocate(client, scope, key).await;
        let kind = if fields.is_some() { "one" } else { "absent" };
        let rows = fields
            .map(|fields| serde_json::json!([{"source_key":key,"fields":fields}]))
            .unwrap_or_else(|| serde_json::json!([]));
        let result:String=client.query_one("SELECT registry_internal.publish_external_projection($1,$2,$3,$4,$5,$6,$7,999,1059,$8,$9)",&[&scope.projection_id,&scope.epoch,&scope.binding_digest,&scope.grant_digest,&sequence,&key,&id,&kind,&rows]).await.unwrap().get(0);
        assert_eq!(result, "published");
    }

    async fn allocate(client: &Client, scope: &ProjectionScope, key: &str) -> i64 {
        client
            .query_one(
                "SELECT registry_internal.allocate_external_projection_refresh($1,$2,$3,$4,$5,120)",
                &[
                    &scope.projection_id,
                    &scope.epoch,
                    &scope.binding_digest,
                    &scope.grant_digest,
                    &key,
                ],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn publish_collection(
        client: &Client,
        scope: &ProjectionScope,
        key: &str,
        members: &[(&str, &str)],
    ) {
        let sequence = allocate(client, scope, key).await;
        let rows = Value::Array(
            members
                .iter()
                .map(|(member, label)| {
                    serde_json::json!({"source_key": member, "fields": {"label": label}})
                })
                .collect(),
        );
        let result:String=client.query_one("SELECT registry_internal.publish_external_projection($1,$2,$3,$4,$5,$6,$7,999,1059,'complete-collection',$8)",&[&scope.projection_id,&scope.epoch,&scope.binding_digest,&scope.grant_digest,&sequence,&key,&key,&rows]).await.unwrap().get(0);
        assert_eq!(result, "published");
    }

    #[tokio::test]
    async fn root_rls_coverage_filter_count_and_bidirectional_null_paging_share_one_population() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        let registry = super::tests::registry();
        super::super::install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        install(&migration, &database.runtime_role).await.unwrap();
        migration
            .batch_execute(&INSTALL_SQL.replace(
                "floor(extract(epoch FROM clock_timestamp()))::bigint",
                "1000",
            ))
            .await
            .unwrap();
        let scope =
            ProjectionScope::new("projection", Uuid::new_v4(), "binding", "grant", 60).unwrap();
        configure_scope(&migration, &scope).await.unwrap();
        let entity = &registry.entities()["local-record"];
        let key = &entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == "subject-key")
            .unwrap()
            .physical_name;
        let tenant = &entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == "tenant")
            .unwrap()
            .physical_name;
        database.admin.batch_execute(&format!("INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{key}\",\"{tenant}\") VALUES ('00000000-0000-4000-8000-000000000001','fixture','first','allowed'),('00000000-0000-4000-8000-000000000002','fixture','absent','allowed'),('00000000-0000-4000-8000-000000000003','fixture','uncovered','allowed'),('00000000-0000-4000-8000-000000000004','fixture','hidden','other')",entity.physical_table)).await.unwrap();
        publish(&migration, &scope, "first", Some("A"), "first").await;
        publish(&migration, &scope, "absent", None, "absent").await;
        let (runtime, connection) = database
            .runtime_config
            .postgres()
            .connect(NoTls)
            .await
            .unwrap();
        let runtime_task = tokio::spawn(async move {
            connection.await.expect("query fixture connection");
        });
        runtime.batch_execute("SET registry.access_profile='reader'; SET registry.principal='staff'; SET registry.purpose='consultation'; SET registry.row_boundaries='[{\"field\":\"tenant\",\"operator\":\"equals\",\"values\":[\"allowed\"]}]';").await.unwrap();
        // Publication leaves the configured scope generation unchanged.
        let mut request = super::tests::request(&scope, 0);
        request.include_count = true;
        request.filter = Some(ExactFilter {
            field: "label".to_owned(),
            value: Value::String("A".to_owned()),
        });
        let incomplete = run(&runtime, &registry, &request).await;
        assert!(!incomplete.get::<_, bool>(1));
        assert_eq!(incomplete.get::<_, Option<i64>>(4), None);
        assert_eq!(incomplete.get::<_, Value>(5), serde_json::json!([]));
        publish(&migration, &scope, "uncovered", Some("B"), "third").await;
        let complete = run(&runtime, &registry, &request).await;
        assert!(complete.get::<_, bool>(1));
        assert_eq!(complete.get::<_, Option<i64>>(4), Some(1));
        let rows: Vec<ExternalViewRow> = serde_json::from_value(complete.get(5)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fields["label"], "A");
        request.filter = None;
        request.order = Some(ExternalOrder {
            field: "label".to_owned(),
            direction: SortDirection::Descending,
        });
        request.page_size = 1;
        let first = run(&runtime, &registry, &request).await;
        assert_eq!(first.get::<_, Option<i64>>(4), Some(3));
        let rows: Vec<ExternalViewRow> = serde_json::from_value(first.get(5)).unwrap();
        assert_eq!(rows[0].fields["label"], "B");
        request.after = Some(PageAfter {
            root_id: rows[0].root_id,
            source_key: rows[0].source_key.clone(),
            sort_value: rows[0].sort_value.clone(),
        });
        let second = run(&runtime, &registry, &request).await;
        let rows: Vec<ExternalViewRow> = serde_json::from_value(second.get(5)).unwrap();
        assert_eq!(rows[0].fields["label"], "A");
        request.after = Some(PageAfter {
            root_id: rows[0].root_id,
            source_key: rows[0].source_key.clone(),
            sort_value: rows[0].sort_value.clone(),
        });
        let last = run(&runtime, &registry, &request).await;
        let rows: Vec<ExternalViewRow> = serde_json::from_value(last.get(5)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].availability, ExternalAvailability::Absent);
        assert_eq!(rows[0].fields, serde_json::json!({}));
        request.after = None;
        request.order.as_mut().unwrap().direction = SortDirection::Ascending;
        let ascending = run(&runtime, &registry, &request).await;
        let rows: Vec<ExternalViewRow> = serde_json::from_value(ascending.get(5)).unwrap();
        assert_eq!(rows[0].fields["label"], "A");
        // Pause the compiled query after it has read coverage. PostgreSQL
        // must use that statement's snapshot even after another transaction
        // commits a root that has no projection.
        request.page_size = 10;
        let mut gated = compile(&registry, &request).unwrap();
        assert!(gated.sql.contains("coverage AS MATERIALIZED ("));
        assert!(gated.sql.contains("), matched AS MATERIALIZED ("));
        gated.sql = gated
            .sql
            .replacen(
                "coverage AS MATERIALIZED (",
                "coverage_snapshot AS MATERIALIZED (",
                1,
            )
            .replacen(
                "), matched AS MATERIALIZED (",
                "), coverage AS MATERIALIZED (
                    SELECT coverage_snapshot.*, pg_catalog.pg_advisory_xact_lock(732995003)
                    FROM coverage_snapshot
                ), matched AS MATERIALIZED (",
                1,
            );
        let reader_pid: i32 = runtime
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        migration
            .execute("SELECT pg_advisory_lock(732995003)", &[])
            .await
            .unwrap();
        let insert_uncovered_root = async {
            let waited = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let waiting: bool = database
                        .admin
                        .query_one(
                            "SELECT EXISTS (SELECT 1 FROM pg_locks
                         WHERE locktype='advisory' AND NOT granted AND pid=$1)",
                            &[&reader_pid],
                        )
                        .await
                        .unwrap()
                        .get(0);
                    if waiting {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok();
            if waited {
                database.admin.execute(
                    &format!("INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{key}\",\"{tenant}\")
                        VALUES ('00000000-0000-4000-8000-000000000006','fixture','new-uncovered','allowed')", entity.physical_table),
                    &[],
                ).await.unwrap();
            }
            migration
                .execute("SELECT pg_advisory_unlock(732995003)", &[])
                .await
                .unwrap();
            assert!(waited, "the query reached the coverage barrier");
        };
        let (racing_page, ()) =
            tokio::join!(run_statement(&runtime, &gated), insert_uncovered_root);
        assert!(racing_page.get::<_, bool>(1));
        assert_eq!(racing_page.get::<_, Option<i64>>(4), Some(3));
        let rows: Vec<ExternalViewRow> = serde_json::from_value(racing_page.get(5)).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].fields["label"], "A");
        let after_commit = run(&runtime, &registry, &request).await;
        assert!(!after_commit.get::<_, bool>(1));
        assert_eq!(after_commit.get::<_, Option<i64>>(4), None);
        assert_eq!(after_commit.get::<_, Value>(5), serde_json::json!([]));

        // The eligibility read and publication share the same statement and
        // real generated source relation, including its forced root RLS.
        let relations = ReadRelations::statistics(entity, &["subject-key".to_owned()]).unwrap();
        let subject = relations.field_expression(entity, "subject-key").unwrap();
        let eligibility=format!("SELECT 1 FROM {} WHERE {}=ANY($12::uuid[]) AND ({})::text=$6::text AND current_setting('registry.access_profile',true)='reader'",relations.from_sql,relations.id_expression,subject.sql);
        let sql = super::super::external_projection::publication_statement(&eligibility);
        let ticket:i64=runtime.query_one("SELECT registry_internal.allocate_external_projection_refresh($1,$2,$3,$4,'first',120)",&[&scope.projection_id,&scope.epoch,&scope.binding_digest,&scope.grant_digest]).await.unwrap().get(0);
        let fields = serde_json::json!([{"source_key":"first","fields":{"label":"retained"}}]);
        let roots = vec![Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()];
        let result: String = runtime
            .query_one(
                &sql,
                &[
                    &scope.projection_id,
                    &scope.epoch,
                    &scope.binding_digest,
                    &scope.grant_digest,
                    &ticket,
                    &"first",
                    &"association",
                    &1000_i64,
                    &1060_i64,
                    &"one",
                    &fields,
                    &roots,
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(result, "published");
        let ticket:i64=runtime.query_one("SELECT registry_internal.allocate_external_projection_refresh($1,$2,$3,$4,'first',120)",&[&scope.projection_id,&scope.epoch,&scope.binding_digest,&scope.grant_digest]).await.unwrap().get(0);
        database.admin.batch_execute(&format!("INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{key}\",\"{tenant}\") VALUES ('00000000-0000-4000-8000-000000000005','fixture','first','allowed'); UPDATE registry_data.\"{}\" SET \"{key}\"='detached' WHERE record_id='00000000-0000-4000-8000-000000000001'; UPDATE registry_data.\"{}\" SET \"{key}\"='first' WHERE record_id='00000000-0000-4000-8000-000000000004';",entity.physical_table,entity.physical_table,entity.physical_table)).await.unwrap();
        for id in [
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000004",
        ] {
            let roots = vec![Uuid::parse_str(id).unwrap()];
            let result: String = runtime
                .query_one(
                    &sql,
                    &[
                        &scope.projection_id,
                        &scope.epoch,
                        &scope.binding_digest,
                        &scope.grant_digest,
                        &ticket,
                        &"first",
                        &"rejected",
                        &1000_i64,
                        &1060_i64,
                        &"one",
                        &fields,
                        &roots,
                    ],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(result, "ineligible");
        }
        assert_eq!(runtime.query_one("SELECT fields->>'label' FROM registry_internal.registry_external_projection_values WHERE projection_id='projection' AND subject_key='first'",&[]).await.unwrap().get::<_,String>(0),"retained");
        runtime_task.abort();
        migration_task.abort();
        drop(runtime);
        drop(migration);
        database.cleanup().await;
    }

    /// The SQL form of the link-key rule agrees with the Rust predicate on
    /// every boundary: byte length, control characters, and the leading and
    /// trailing white space `str::trim` removes.
    #[tokio::test]
    async fn the_sql_link_key_rule_agrees_with_the_rust_predicate() {
        let database = harness::TestDatabase::create(2).await;
        let sql = format!(
            "SELECT {} FROM (SELECT $1::text AS raw_key) AS linked",
            crate::external_views::acceptable_link_key_sql("raw_key")
        );
        let max = "a".repeat(512);
        let over = "a".repeat(513);
        let wide_max = "\u{E9}".repeat(256);
        let wide_over = "\u{E9}".repeat(257);
        let mut keys = vec![
            "plain".to_owned(),
            "inner space".to_owned(),
            "dash-and_dot.9".to_owned(),
            max,
            over,
            wide_max,
            wide_over,
            "\u{1D518}key".to_owned(),
        ];
        for edge in [
            '\u{1}', '\u{7}', '\u{1f}', '\u{7f}', '\u{80}', '\u{9f}', '\u{a0}', '\u{a1}', '\u{85}',
            '\u{1680}', '\u{2000}', '\u{200a}', '\u{200b}', '\u{2028}', '\u{2029}', '\u{202f}',
            '\u{205f}', '\u{3000}', ' ', '\t', '\n', '\r', '\u{b}', '\u{c}', '\u{e000}',
            '\u{feff}',
        ] {
            for key in [
                format!("{edge}key"),
                format!("key{edge}"),
                format!("ke{edge}y"),
            ] {
                keys.push(key);
            }
        }
        for key in keys {
            let accepted: Option<String> = database
                .admin
                .query_one(&sql, &[&key])
                .await
                .unwrap()
                .get(0);
            assert_eq!(
                accepted.is_some(),
                crate::external_views::link_key_acceptable(&key),
                "{:?}",
                key.chars().take(8).collect::<String>()
            );
            assert_eq!(
                crate::external_views::link_key_acceptable(&key),
                registry_adapter_core::projection_token_valid(&key),
                "the write-time rule is the source contract's selector rule"
            );
        }
        for key in ["", "ok"] {
            let accepted: Option<String> = database
                .admin
                .query_one(&sql, &[&key])
                .await
                .unwrap()
                .get(0);
            assert_eq!(accepted.as_deref(), Some(key));
        }
        let none: Option<String> = database
            .admin
            .query_one(&sql, &[&Option::<String>::None])
            .await
            .unwrap()
            .get(0);
        assert_eq!(none, None);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn a_date_cursor_reads_the_same_under_any_date_style() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        let mut project = super::tests::project();
        project["externalRecordTypes"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"id":"issued","type":"date","classification":"internal"}));
        for path in [
            "/externalProjections/0/fields",
            "/externalViews/0/links/0/fields",
            "/accessProfiles/0/permissions/externalViews/0/links/0/readableFields",
            "/accessProfiles/0/permissions/externalViews/0/links/0/sortableFields",
        ] {
            project
                .pointer_mut(path)
                .and_then(Value::as_array_mut)
                .unwrap()
                .push(Value::from("issued"));
        }
        let registry = super::tests::compile_project(&project);
        super::super::install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        install(&migration, &database.runtime_role).await.unwrap();
        migration
            .batch_execute(&INSTALL_SQL.replace(
                "floor(extract(epoch FROM clock_timestamp()))::bigint",
                "1000",
            ))
            .await
            .unwrap();
        let scope =
            ProjectionScope::new("projection", Uuid::new_v4(), "binding", "grant", 60).unwrap();
        configure_scope(&migration, &scope).await.unwrap();
        let entity = &registry.entities()["local-record"];
        let column = |id: &str| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == id)
                .unwrap()
                .physical_name
                .clone()
        };
        database.admin.batch_execute(&format!("INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{}\",\"{}\") VALUES ('00000000-0000-4000-8000-000000000001','fixture','first','allowed'),('00000000-0000-4000-8000-000000000002','fixture','second','allowed')",entity.physical_table,column("subject-key"),column("tenant"))).await.unwrap();
        for (key, label, issued) in [("first", "A", "2026-01-02"), ("second", "B", "2026-02-01")] {
            let fields = serde_json::json!({"label": label, "issued": issued});
            publish_fields(&migration, &scope, key, Some(fields), key).await;
        }
        let (runtime, connection) = database
            .runtime_config
            .postgres()
            .connect(NoTls)
            .await
            .unwrap();
        let runtime_task = tokio::spawn(async move {
            connection.await.expect("query fixture connection");
        });
        runtime.batch_execute("SET registry.access_profile='reader'; SET registry.principal='staff'; SET registry.purpose='consultation'; SET registry.row_boundaries='[{\"field\":\"tenant\",\"operator\":\"equals\",\"values\":[\"allowed\"]}]';").await.unwrap();
        // A database default can choose any date output style.
        runtime
            .batch_execute("SET DateStyle='SQL, DMY'")
            .await
            .unwrap();
        let mut request = super::tests::request(&scope, 0);
        request.order = Some(ExternalOrder {
            field: "issued".to_owned(),
            direction: SortDirection::Ascending,
        });
        request.page_size = 1;
        let first = run(&runtime, &registry, &request).await;
        let rows: Vec<ExternalViewRow> = serde_json::from_value(first.get(5)).unwrap();
        assert_eq!(rows[0].fields["label"], "A");
        assert_eq!(rows[0].sort_value.as_deref(), Some("2026-01-02"));
        request.after = Some(PageAfter {
            root_id: rows[0].root_id,
            source_key: rows[0].source_key.clone(),
            sort_value: rows[0].sort_value.clone(),
        });
        let second = run(&runtime, &registry, &request).await;
        let rows: Vec<ExternalViewRow> = serde_json::from_value(second.get(5)).unwrap();
        assert_eq!(rows[0].fields["label"], "B");
        runtime_task.abort();
        migration_task.abort();
        drop(runtime);
        drop(migration);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn an_unlinked_root_reads_as_a_complete_empty_related_collection() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        let mut project = super::tests::project();
        project["externalProjections"][0]["cardinality"] = Value::from("many");
        let registry = super::tests::compile_project(&project);
        super::super::install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        install(&migration, &database.runtime_role).await.unwrap();
        migration
            .batch_execute(&INSTALL_SQL.replace(
                "floor(extract(epoch FROM clock_timestamp()))::bigint",
                "1000",
            ))
            .await
            .unwrap();
        let scope =
            ProjectionScope::new("projection", Uuid::new_v4(), "binding", "grant", 60).unwrap();
        configure_scope(&migration, &scope).await.unwrap();
        let entity = &registry.entities()["local-record"];
        let column = |id: &str| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == id)
                .unwrap()
                .physical_name
                .clone()
        };
        // Roots 2 and 3 name no outside subject: one leaves the link field
        // unset, the other empty. Root 6 is unlinked too, but outside the
        // caller's rows.
        database.admin.batch_execute(&format!("INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{}\",\"{}\") VALUES ('{}','fixture','family','allowed'),('{}','fixture',NULL,'allowed'),('{}','fixture','','allowed'),('{}','fixture','pending','allowed'),('{}','fixture','empty','allowed'),('{}','fixture',NULL,'other')",entity.physical_table,column("subject-key"),column("tenant"),root(1),root(2),root(3),root(4),root(5),root(6))).await.unwrap();
        publish_collection(&migration, &scope, "family", &[("m2", "B"), ("m1", "A")]).await;
        publish_collection(&migration, &scope, "empty", &[]).await;
        let (runtime, connection) = database
            .runtime_config
            .postgres()
            .connect(NoTls)
            .await
            .unwrap();
        let runtime_task = tokio::spawn(async move {
            connection.await.expect("query fixture connection");
        });
        runtime.batch_execute("SET registry.access_profile='reader'; SET registry.principal='staff'; SET registry.purpose='consultation'; SET registry.row_boundaries='[{\"field\":\"tenant\",\"operator\":\"equals\",\"values\":[\"allowed\"]}]';").await.unwrap();
        let mut request = super::tests::request(&scope, 0);
        // A related collection is read for one root at a time.
        assert!(matches!(
            compile(&registry, &request),
            Err(ExternalQueryError::NotPermitted)
        ));
        // Each case: root, complete, found, earliest expiry, member labels.
        type Case = (u32, bool, bool, Option<i64>, &'static [&'static str]);
        let cases: [Case; 6] = [
            (1, true, true, Some(1059), &["A", "B"]),
            (2, true, true, None, &[]),
            (3, true, true, None, &[]),
            (4, false, true, None, &[]),
            (5, true, true, Some(1059), &[]),
            (6, true, false, None, &[]),
        ];
        for (id, complete, found, expires_at, labels) in cases {
            let id = root(id);
            request.root_id = Some(id);
            let result = run(&runtime, &registry, &request).await;
            assert!(result.get::<_, bool>(0), "{id}: the generation holds");
            assert_eq!(result.get::<_, bool>(1), complete, "{id}: complete");
            assert_eq!(result.get::<_, bool>(2), found, "{id}: found");
            assert_eq!(result.get::<_, Option<i64>>(3), expires_at, "{id}: expiry");
            let rows: Vec<ExternalViewRow> = serde_json::from_value(result.get(5)).unwrap();
            assert!(
                rows.iter()
                    .all(|row| row.root_id == id
                        && row.availability == ExternalAvailability::Available),
                "{id}"
            );
            assert_eq!(
                rows.iter()
                    .map(|row| row.fields["label"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                labels,
                "{id}: members"
            );
        }
        runtime_task.abort();
        migration_task.abort();
        drop(runtime);
        drop(migration);
        database.cleanup().await;
    }

    fn plan_nodes<'a>(plan: &'a Value, nodes: &mut Vec<&'a Value>) {
        nodes.push(plan);
        for child in plan["Plans"].as_array().into_iter().flatten() {
            plan_nodes(child, nodes);
        }
    }

    fn root(g: u32) -> Uuid {
        Uuid::parse_str(&format!("00000000-0000-4000-8000-{g:012x}")).unwrap()
    }

    #[tokio::test]
    async fn an_indexed_read_looks_up_each_root_snapshot_by_its_primary_key() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        let registry = super::tests::registry();
        super::super::install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        install(&migration, &database.runtime_role).await.unwrap();
        migration
            .batch_execute(&INSTALL_SQL.replace(
                "floor(extract(epoch FROM clock_timestamp()))::bigint",
                "1000",
            ))
            .await
            .unwrap();
        let scope =
            ProjectionScope::new("projection", Uuid::new_v4(), "binding", "grant", 60).unwrap();
        configure_scope(&migration, &scope).await.unwrap();
        let entity = &registry.entities()["local-record"];
        let column = |id: &str| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == id)
                .unwrap()
                .physical_name
                .clone()
        };
        // A dense scope: every root holds a fresh value. Every thousandth
        // root belongs to a narrow tenant.
        database
            .admin
            .batch_execute(&format!(
                "INSERT INTO registry_data.\"{table}\" (record_id,active_package_revision,\"{key}\",\"{tenant}\")
                 SELECT ('00000000-0000-4000-8000-'||lpad(to_hex(g),12,'0'))::uuid,'fixture','key-'||g,
                        CASE WHEN g % 1000 = 0 THEN 'narrow' ELSE 'allowed' END
                 FROM generate_series(1,20000) AS g;
                 INSERT INTO registry_internal.registry_external_projection_snapshots
                     (projection_id,epoch,subject_key,snapshot_id,observed_at,expires_at,refresh_sequence,kind)
                 SELECT 'projection','{epoch}'::uuid,'key-'||g,'snapshot-'||g,990,1050,g,'one'
                 FROM generate_series(1,20000) AS g;
                 INSERT INTO registry_internal.registry_external_projection_values
                     (projection_id,epoch,subject_key,source_key,fields)
                 SELECT 'projection','{epoch}'::uuid,'key-'||g,'key-'||g,jsonb_build_object('label','label-'||g)
                 FROM generate_series(1,20000) AS g;
                 ANALYZE registry_data.\"{table}\";
                 ANALYZE registry_internal.registry_external_projection_snapshots;
                 ANALYZE registry_internal.registry_external_projection_values;",
                table = entity.physical_table,
                key = column("subject-key"),
                tenant = column("tenant"),
                epoch = scope.epoch,
            ))
            .await
            .unwrap();
        let (runtime, connection) = database
            .runtime_config
            .postgres()
            .connect(NoTls)
            .await
            .unwrap();
        let runtime_task = tokio::spawn(async move {
            connection.await.expect("query fixture connection");
        });
        runtime.batch_execute("SET registry.access_profile='reader'; SET registry.principal='staff'; SET registry.purpose='consultation';").await.unwrap();

        let mut detail = super::tests::request(&scope, 0);
        detail.root_id = Some(root(10_001));
        let mut narrow = super::tests::request(&scope, 0);
        narrow.include_count = true;
        // A list page reads its rows and one lookahead row.
        for (tenant, request, expected) in [("allowed", &detail, 1_usize), ("narrow", &narrow, 11)]
        {
            runtime
                .batch_execute(&format!("SET registry.row_boundaries='[{{\"field\":\"tenant\",\"operator\":\"equals\",\"values\":[\"{tenant}\"]}}]';"))
                .await
                .unwrap();
            let statement = compile(&registry, request).unwrap();
            let result = run_statement(&runtime, &statement).await;
            assert!(result.get::<_, bool>(1), "{tenant}: coverage is complete");
            let rows: Vec<ExternalViewRow> = serde_json::from_value(result.get(5)).unwrap();
            assert_eq!(rows.len(), expected, "{tenant}");
            assert!(rows
                .iter()
                .all(|row| row.availability == ExternalAvailability::Available));

            let parameters = statement
                .parameters
                .iter()
                .map(|value| {
                    (
                        value as &(dyn tokio_postgres::types::ToSql + Sync),
                        Type::TEXT,
                    )
                })
                .collect::<Vec<_>>();
            let explained: Value = runtime
                .query_typed_one(
                    &format!(
                        "EXPLAIN (ANALYZE, FORMAT JSON, COSTS OFF, TIMING OFF, SUMMARY OFF) {}",
                        statement.sql
                    ),
                    &parameters,
                )
                .await
                .unwrap()
                .get(0);
            let mut nodes = Vec::new();
            plan_nodes(&explained[0]["Plan"], &mut nodes);
            let tables = [
                "registry_external_projection_snapshots",
                "registry_external_projection_values",
            ];
            for table in tables {
                let scans = nodes
                    .iter()
                    .filter(|node| node["Relation Name"] == table)
                    .collect::<Vec<_>>();
                assert!(!scans.is_empty(), "{tenant}: {explained}");
                for node in scans {
                    // Each root's snapshot and value are one primary key
                    // lookup, never a scan of the whole projection.
                    assert_eq!(
                        node["Index Name"],
                        format!("{table}_pkey"),
                        "{tenant}: {explained}"
                    );
                    assert!(
                        node["Index Cond"]
                            .as_str()
                            .is_some_and(|condition| condition.contains("subject_key")),
                        "{tenant}: {explained}"
                    );
                }
            }
            // Only the page's own rows are put in order; no sort reads a
            // projection table.
            for sort in nodes.iter().filter(|node| node["Node Type"] == "Sort") {
                let mut below = Vec::new();
                plan_nodes(sort, &mut below);
                assert!(
                    !below.iter().any(|node| node["Relation Name"]
                        .as_str()
                        .is_some_and(|name| tables.contains(&name))),
                    "{tenant}: {explained}"
                );
            }
            for node in &nodes {
                if node["Relation Name"] == entity.physical_table.as_str() {
                    // The root table read follows the authorized population,
                    // which this test does not bound.
                    continue;
                }
                let loops = node["Actual Loops"].as_f64().unwrap_or(1.0);
                let rows = node["Actual Rows"].as_f64().unwrap_or(0.0) * loops;
                let removed = node["Rows Removed by Filter"].as_f64().unwrap_or(0.0) * loops;
                assert!(
                    rows + removed <= 60.0,
                    "{tenant}: each node reads about the authorized roots: {explained}"
                );
            }
        }
        runtime_task.abort();
        migration_task.abort();
        drop(runtime);
        drop(migration);
        database.cleanup().await;
    }
}

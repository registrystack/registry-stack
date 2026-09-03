// SPDX-License-Identifier: Apache-2.0
//! One canonical cursor binding contract for HTTP, live reads and history.

use crate::api::{
    cursor_query_reference_value, AuthorizedRequestContext, CursorQueryReferenceInput,
    ReadFilterExpr, ReadFilterOperator, ReadLogicalOp, ReadOrderClause, ReadProjectionField,
    ReadSpatialQuery, RowBoundaryOperator,
};
use crate::cursor::{
    CursorAdapter, CursorCodec, CursorError, CursorQueryScope, CursorRepresentation,
};
use crate::model::CompiledQueryOperation;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) struct CursorBindingReferences {
    pub(crate) principal: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) row_boundary: String,
    pub(crate) projection: String,
    pub(crate) spatial: Option<String>,
    pub(crate) query: String,
    pub(crate) sort: String,
    pub(crate) scope: String,
}

#[derive(Clone, Copy)]
pub(crate) struct CursorBindingQuery<'a> {
    pub(crate) selected_fields: &'a BTreeSet<String>,
    pub(crate) projection: &'a [ReadProjectionField],
    pub(crate) filter: Option<&'a ReadFilterExpr>,
    pub(crate) spatial: Option<&'a ReadSpatialQuery>,
    pub(crate) order: Option<&'a ReadOrderClause>,
    pub(crate) include_count: bool,
    pub(crate) page_size: u16,
    pub(crate) temporal_instant: Option<&'a str>,
    pub(crate) scope: &'a CursorQueryScope,
    pub(crate) representation: CursorRepresentation,
    pub(crate) adapter: CursorAdapter,
    pub(crate) adapter_origin: Option<&'a str>,
}

pub(crate) fn references(
    cursors: &CursorCodec,
    route_id: &str,
    operation: &CompiledQueryOperation,
    context: &AuthorizedRequestContext,
    query: CursorBindingQuery<'_>,
) -> Result<CursorBindingReferences, CursorError> {
    let principal_reference = context
        .principal()
        .map(|principal| {
            cursors.binding_digest_bytes(b"breg-cursor-principal-v3", principal.as_bytes())
        })
        .transpose()?;
    let purpose_reference = context
        .purpose()
        .map(|purpose| cursors.binding_digest_bytes(b"breg-cursor-purpose-v3", purpose.as_bytes()))
        .transpose()?;
    let row_boundary_reference = cursors.binding_digest(
        b"breg-cursor-row-boundary-v3",
        &json!(context
            .row_boundaries()
            .iter()
            .map(|boundary| {
                json!({
                    "field": boundary.field(),
                    "operator": match boundary.operator() {
                        RowBoundaryOperator::Equals => "equals",
                        RowBoundaryOperator::In => "in",
                    },
                    "values": boundary.values(),
                })
            })
            .collect::<Vec<_>>()),
    )?;
    let projection_reference = cursors.binding_digest(
        b"breg-cursor-projection-v3",
        &json!({"projection": query.projection.iter().map(projection_field_value).collect::<Vec<_>>()}),
    )?;
    let spatial_reference = query
        .spatial
        .map(|spatial| {
            cursors.binding_digest(
                b"breg-cursor-spatial-v3",
                &read_spatial_query_value(spatial),
            )
        })
        .transpose()?;
    let query_reference = cursors.binding_digest(
        b"breg-cursor-query-v3",
        &cursor_query_reference_value(CursorQueryReferenceInput {
            route_id,
            query_operation_id: &operation.id,
            query_kind: operation.kind,
            selected_profile: context.selected_profile(),
            projection: query
                .projection
                .iter()
                .map(projection_field_value)
                .collect::<Vec<_>>(),
            filter: query.filter.map(read_filter_expr_value),
            spatial: query.spatial.map(read_spatial_query_value),
            order: query.order.map(read_order_clause_value),
            page_size: query.page_size,
            include_count: query.include_count,
            temporal_instant: query.temporal_instant,
            scope: cursor_scope_value(query.scope),
            representation: query.representation,
            adapter: query.adapter,
            adapter_origin: query.adapter_origin,
        }),
    )?;
    let sort_reference = cursors.binding_digest(
        b"breg-cursor-sort-v3",
        &json!({"order": query.order.map(read_order_clause_value), "tieBreaker": operation.stable_tie_breaker}),
    )?;
    let scope_reference =
        cursors.binding_digest(b"breg-cursor-scope-v3", &cursor_scope_value(query.scope))?;
    Ok(CursorBindingReferences {
        principal: principal_reference,
        purpose: purpose_reference,
        row_boundary: row_boundary_reference,
        projection: projection_reference,
        spatial: spatial_reference,
        query: query_reference,
        sort: sort_reference,
        scope: scope_reference,
    })
}

fn read_spatial_query_value(spatial: &ReadSpatialQuery) -> Value {
    json!({
        "bbox": {
            "geometryField": spatial.bbox.geometry_field,
            "west": spatial.bbox.west,
            "south": spatial.bbox.south,
            "east": spatial.bbox.east,
            "north": spatial.bbox.north,
            "maximumLongitudeSpanDegrees": spatial.bbox.maximum_longitude_span_degrees,
            "maximumLatitudeSpanDegrees": spatial.bbox.maximum_latitude_span_degrees,
        }
    })
}

fn projection_field_value(field: &ReadProjectionField) -> Value {
    json!({
        "fieldId": field.field_id,
        "fieldType": field.field_type,
    })
}

fn read_order_clause_value(order: &ReadOrderClause) -> Value {
    json!({
        "fieldId": order.field_id,
        "fieldType": order.field_type,
        "direction": order.direction,
    })
}

fn cursor_scope_value(scope: &CursorQueryScope) -> Value {
    match scope {
        CursorQueryScope::Collection {} => json!({"kind": "collection"}),
        CursorQueryScope::Relationship { path_id, root_id } => json!({
            "kind": "relationship",
            "pathId": path_id,
            "rootId": root_id,
        }),
        CursorQueryScope::Snapshot { reference } => json!({
            "kind": "snapshot",
            "reference": reference,
        }),
    }
}

fn read_filter_expr_value(filter: &ReadFilterExpr) -> Value {
    match filter {
        ReadFilterExpr::Binary { op, left, right } => json!({
            "kind": "binary",
            "op": match op {
                ReadLogicalOp::And => "and",
                ReadLogicalOp::Or => "or",
            },
            "left": read_filter_expr_value(left),
            "right": read_filter_expr_value(right),
        }),
        ReadFilterExpr::Not(expr) => json!({
            "kind": "not",
            "op": "not",
            "expr": read_filter_expr_value(expr),
        }),
        ReadFilterExpr::Group(expr) => json!({
            "kind": "group",
            "op": "group",
            "expr": read_filter_expr_value(expr),
        }),
        ReadFilterExpr::Predicate(predicate) => json!({
            "kind": "predicate",
            "fieldId": predicate.field_id,
            "fieldType": predicate.field_type,
            "operator": read_filter_operator_name(predicate.operator),
            "values": predicate.values,
        }),
    }
}

fn read_filter_operator_name(operator: ReadFilterOperator) -> &'static str {
    match operator {
        ReadFilterOperator::Eq => "eq",
        ReadFilterOperator::Ne => "ne",
        ReadFilterOperator::Lt => "lt",
        ReadFilterOperator::Le => "le",
        ReadFilterOperator::Gt => "gt",
        ReadFilterOperator::Ge => "ge",
        ReadFilterOperator::In => "in",
        ReadFilterOperator::IsNull => "is_null",
        ReadFilterOperator::IsNotNull => "is_not_null",
        ReadFilterOperator::StartsWith => "startswith",
        ReadFilterOperator::Contains => "contains",
    }
}

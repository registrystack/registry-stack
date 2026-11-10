// SPDX-License-Identifier: Apache-2.0
//! OpenAPI for the external view surface, using the same named link grants.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::contract::Operation;
use crate::external_views::{
    CompiledExternalViews, ExternalCardinality, ExternalFieldType, ExternalLinkPermissionSource,
    ExternalProjectionMode, ExternalRecordTypeSource,
};

pub(crate) fn append(
    paths: &mut Map<String, Value>,
    inventory: &CompiledExternalViews,
    admitted: impl Fn(&str, &str, &str, Operation) -> bool,
) {
    for view in inventory.views.values() {
        for link in &view.links {
            let projection = &inventory.projections[link.projection.as_str()];
            let external = &inventory.record_types[projection.record_type.as_str()];
            let base = format!("/v1/external-views/{}/{}", view.id, link.id);
            let grants = |operation: Operation| {
                inventory
                    .grants
                    .iter()
                    .filter_map(|(profile, views)| {
                        if !admitted(
                            profile,
                            view.record_type.as_str(),
                            projection.purpose.as_str(),
                            operation,
                        ) {
                            return None;
                        }
                        views
                            .get(view.id.as_str())?
                            .links
                            .iter()
                            .find(|grant| grant.link == link.id)
                    })
                    .collect::<Vec<_>>()
            };
            let label = link.label.as_ref().map(|label| {
                &inventory.record_types[inventory.projections[label.projection.as_str()]
                    .record_type
                    .as_str()]
            });
            let detail = grants(Operation::Get);
            let is_indexed = projection.mode == ExternalProjectionMode::Indexed;
            let is_many = projection.cardinality == ExternalCardinality::Many;
            if !detail.is_empty() {
                paths.insert(
                    format!("{base}/records/{{root}}"),
                    json!({"get": read_operation(
                        view.id.as_str(), link.id.as_str(), true, is_indexed && is_many,
                        is_many, external, label, &detail
                    )}),
                );
            }
            if is_indexed && !is_many {
                let collection = grants(Operation::List);
                if !collection.is_empty() {
                    paths.insert(
                        format!("{base}/records"),
                        json!({"get": read_operation(
                            view.id.as_str(), link.id.as_str(), false, true,
                            false, external, None, &collection
                        )}),
                    );
                }
            }
            let refresh_admitted = |labels: bool| {
                is_indexed
                    && inventory.refresh.iter().any(|(profile, projections)| {
                        projections.contains(&projection.id)
                            && (!labels
                                || (is_many
                                    && link.label.as_ref().is_some_and(|label| {
                                        projections.contains(&label.projection)
                                    })))
                            && admitted(
                                profile,
                                view.record_type.as_str(),
                                projection.purpose.as_str(),
                                Operation::List,
                            )
                    })
            };
            for (suffix, summary, labels) in [
                (
                    "refresh",
                    "Refresh a bounded page of authorised local roots",
                    false,
                ),
                (
                    "refresh-labels",
                    "Refresh labels selected from fresh authorised related rows",
                    true,
                ),
            ] {
                if refresh_admitted(labels) {
                    paths.insert(
                        format!("{base}/{suffix}"),
                        refresh_operation(
                            format!("external-{}-{}-{suffix}", view.id, link.id),
                            summary,
                        ),
                    );
                }
            }
        }
    }
}

fn refresh_operation(operation_id: String, summary: &str) -> Value {
    json!({"post": {
        "operationId": operation_id,
        "summary": summary,
        "security": [{"bearerAuth": []}],
        "parameters": [profile_parameter(), size_parameter(), cursor_parameter()],
        "responses": {
            "200": {"description": "Value-free refresh report", "content": {"application/json": {"schema": {
                "type": "object", "additionalProperties": false,
                "required": ["processed", "published", "reused", "unavailable"],
                "properties": {"processed": count_schema(), "published": count_schema(),
                    "reused": count_schema(), "unavailable": count_schema(), "nextCursor": {"type":"string"}}
            }}}},
            "400": {"description": "Invalid page request"},
            "404": {"description": "Refresh is unavailable to the caller"},
            "503": {"description": "The current source or projection is unavailable"}
        }
    }})
}

#[allow(clippy::too_many_arguments)]
fn read_operation(
    view: &str,
    link: &str,
    detail: bool,
    pageable: bool,
    many: bool,
    external: &ExternalRecordTypeSource,
    label: Option<&ExternalRecordTypeSource>,
    grants: &[&ExternalLinkPermissionSource],
) -> Value {
    let mut parameters = vec![profile_parameter()];
    if detail {
        parameters.push(json!({"name":"root","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
    }
    let allow_count = pageable && grants.iter().any(|grant| grant.allow_count);
    if pageable {
        parameters.extend([size_parameter(), cursor_parameter()]);
        if grants
            .iter()
            .any(|grant| !grant.filterable_fields.is_empty())
        {
            parameters.push(json!({"name":"$filter","in":"query","description":"Exact equality on a granted field","schema":{"type":"string"}}));
        }
        if grants.iter().any(|grant| !grant.sortable_fields.is_empty()) {
            parameters.push(json!({"name":"$orderby","in":"query","description":"One granted field; missing values sort last","schema":{"type":"string"}}));
        }
        if allow_count {
            parameters.push(json!({"name":"$count","in":"query","schema":{"type":"boolean"}}));
        }
    }
    let readable = grants
        .iter()
        .flat_map(|grant| grant.readable_fields.iter().map(|id| id.as_str()))
        .collect::<BTreeSet<_>>();
    let mut row = json!({
        "rootId": {"type":"string","format":"uuid"},
        "availability": availability_schema(),
        "fields": fields(external, &readable)
    });
    if many {
        row["rowId"] = json!({"type":"string","description":"Opaque stable row handle within this link and root"});
    }
    let label_fields = grants
        .iter()
        .flat_map(|grant| grant.label_fields.iter().map(|id| id.as_str()))
        .collect::<BTreeSet<_>>();
    if let Some(label) = label.filter(|_| !label_fields.is_empty()) {
        row["label"] = json!({
            "type":"object","additionalProperties":false,"required":["authority","availability","fields"],
            "properties":{"authority":{"const":label.authority},"availability":availability_schema(),"fields":fields(label,&label_fields)}
        });
    }
    let mut properties = json!({
        "status": {"enum":["available","unavailable"]},
        "authority": {"const":external.authority},
        "records": {"type":"array","items":{"type":"object","additionalProperties":false,
            "required":["rootId","availability","fields"],"properties":row}}
    });
    if pageable {
        properties["nextCursor"] = json!({"type":"string"});
    }
    if allow_count {
        properties["count"] = count_schema();
    }
    let suffix = if detail { "detail" } else { "list" };
    json!({
        "operationId":format!("external-{view}-{link}-{suffix}"),
        "summary":"Read a named view of external records",
        "security":[{"bearerAuth":[]}],
        "parameters":parameters,
        "responses":{
            "200":{"description":"The external fields available under the selected local grant","content":{"application/json":{"schema":{
                "type":"object","additionalProperties":false,"required":["status","authority","records"],"properties":properties
            }}}},
            "400":{"description":"Invalid query or continuation"},
            "404":{"description":"The view or root is unavailable to the caller"},
            "503":{"description":"The external result is unavailable or indexed coverage is incomplete"}
        }
    })
}

fn fields(external: &ExternalRecordTypeSource, readable: &BTreeSet<&str>) -> Value {
    let properties = external
        .fields
        .iter()
        .filter(|field| readable.contains(field.id.as_str()))
        .map(|field| {
            let value = match field.value_type {
                ExternalFieldType::String => json!({"type":"string"}),
                ExternalFieldType::Integer => json!({"type":"integer"}),
                ExternalFieldType::Boolean => json!({"type":"boolean"}),
                ExternalFieldType::Decimal => {
                    json!({"type":"string","pattern":"^-?[0-9]+(\\.[0-9]+)?$"})
                }
                ExternalFieldType::Date => json!({"type":"string","format":"date"}),
                ExternalFieldType::Uuid => json!({"type":"string","format":"uuid"}),
            };
            (
                field.id.to_string(),
                if field.nullable {
                    json!({"anyOf":[value,{"type":"null"}]})
                } else {
                    value
                },
            )
        })
        .collect::<Map<String, Value>>();
    json!({"type":"object","additionalProperties":false,"properties":properties})
}

fn availability_schema() -> Value {
    json!({"enum":["available","absent","unavailable"]})
}

fn profile_parameter() -> Value {
    json!({"name":"accessProfile","in":"query","schema":{"type":"string"}})
}

fn size_parameter() -> Value {
    json!({"name":"$top","in":"query","schema":{"type":"integer","minimum":1,"maximum":100}})
}

fn cursor_parameter() -> Value {
    json!({"name":"$skiptoken","in":"query","description":"Use alone with the same access profile","schema":{"type":"string"}})
}

fn count_schema() -> Value {
    json!({"type":"integer","minimum":0})
}

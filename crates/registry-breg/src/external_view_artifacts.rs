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
    let mut managed_refresh_possible = false;
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
            let refresh_admitted = |operation: Operation| {
                is_indexed
                    && inventory.refresh.iter().any(|(profile, projections)| {
                        projections.contains(&projection.id)
                            && admitted(
                                profile,
                                view.record_type.as_str(),
                                projection.purpose.as_str(),
                                operation,
                            )
                    })
            };
            managed_refresh_possible |= refresh_admitted(Operation::List);
            if refresh_admitted(Operation::Get) {
                paths.insert(
                    format!("{base}/records/{{root}}/refresh"),
                    json!({"post": root_refresh_operation(view.id.as_str(), link.id.as_str())}),
                );
            }
        }
    }
    if managed_refresh_possible {
        append_managed_refresh_paths(paths);
    }
}

fn append_managed_refresh_paths(paths: &mut Map<String, Value>) {
    let plan =
        json!({"name": "plan", "in": "path", "required": true, "schema": {"type": "string"}});
    let body = |schema: Value| {
        json!({
            "required": true, "content": {"application/json": {"schema": schema}}
        })
    };
    paths.insert("/v1/external-refresh-plans/{plan}/source-changes".to_owned(), json!({"post": {
        "operationId": "external-refresh-plan-source-change",
        "summary": "Admit an authenticated source change",
        "security": [{"bearerAuth": []}],
        "parameters": [plan],
        "requestBody": body(json!({"type": "object", "additionalProperties": false,
            "required": ["projection", "selector"],
            "properties": {
                "projection": {"type": "string", "minLength": 1},
                "selector": {"type": "string", "minLength": 1, "maxLength": 512}
            }})),
        "responses": {
            "202": {"description": "Source change queued, without checking local matches; a repeated change updates the queued one"},
            "400": {"description": "Invalid source change"},
            "404": {"description": "Plan or projection is unavailable to the notifier"},
            "429": {"description": "Source change admission is at capacity", "headers": {
                "Retry-After": {"schema": {"type": "integer", "minimum": 1}}
            }},
            "503": {"description": "The current plan or source is unavailable"}
        }
    }}));
}

/// Queue one root for the in-process refresh worker. The caller is a staff
/// application's service client, not a human officer: its selected profile
/// must Get the root and hold `refreshExternalProjections` for the link's
/// projection.
fn root_refresh_operation(view: &str, link: &str) -> Value {
    json!({
        "operationId": format!("external-{view}-{link}-refresh"),
        "summary": "Queue one authorised root for the refresh worker",
        "description": "For a staff application's service client. The in-process refresh worker fetches the root's linked records on its next tick, as the refresh plan's configured identity.",
        "security": [{"bearerAuth": []}],
        "parameters": [
            profile_parameter(),
            {"name":"root","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}
        ],
        "responses": {
            "202": {"description": "The root is queued; a repeated request updates the queued one"},
            "400": {"description": "Invalid refresh request"},
            "404": {"description": "The view, root or refresh grant is unavailable to the caller"},
            "429": {"description": "The refresh queue is at capacity", "headers": {
                "Retry-After": {"schema": {"type": "integer", "minimum": 1}}
            }},
            "503": {"description": "The refresh plan, source or projection is unavailable"}
        }
    })
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

/// The wire schema of a decimal field: the string form BReg's own decimal
/// fields use.
pub(crate) fn decimal_schema() -> Value {
    json!({"type":"string","pattern":"^-?[0-9]+(\\.[0-9]+)?$"})
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
                ExternalFieldType::Decimal => decimal_schema(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(value: &Value) -> BTreeSet<&str> {
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn a_source_change_names_only_the_projection_and_the_selector() {
        let mut paths = Map::new();
        append_managed_refresh_paths(&mut paths);
        assert!(!paths.contains_key("/v1/external-refresh-plans/{plan}/hints"));
        let operation = &paths["/v1/external-refresh-plans/{plan}/source-changes"]["post"];
        assert_eq!(
            operation["operationId"],
            "external-refresh-plan-source-change"
        );
        let schema = &operation["requestBody"]["content"]["application/json"]["schema"];
        assert_eq!(schema["required"], json!(["projection", "selector"]));
        assert_eq!(
            keys(&schema["properties"]),
            BTreeSet::from(["projection", "selector"])
        );
        assert_eq!(
            keys(&operation["responses"]),
            BTreeSet::from(["202", "400", "404", "429", "503"]),
            "a repeated source change is accepted again, never a conflict"
        );
    }

    #[test]
    fn the_in_process_worker_leaves_only_source_changes_on_the_plan_surface() {
        let mut paths = Map::new();
        append_managed_refresh_paths(&mut paths);
        assert_eq!(
            paths.keys().map(String::as_str).collect::<Vec<_>>(),
            ["/v1/external-refresh-plans/{plan}/source-changes"],
            "no caller can drive a refresh plan step over HTTP"
        );
    }

    #[test]
    fn a_root_refresh_queues_one_root_and_returns_no_body() {
        let operation = root_refresh_operation("view", "link");
        assert_eq!(operation["operationId"], "external-view-link-refresh");
        assert!(operation.get("requestBody").is_none());
        assert_eq!(
            operation["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .map(|parameter| parameter["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["accessProfile", "root"]
        );
        assert_eq!(
            keys(&operation["responses"]),
            BTreeSet::from(["202", "400", "404", "429", "503"])
        );
        assert!(operation["responses"]["202"].get("content").is_none());
        assert_eq!(
            operation["responses"]["429"]["headers"]["Retry-After"]["schema"]["minimum"],
            1
        );
    }
}

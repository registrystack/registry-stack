// SPDX-License-Identifier: Apache-2.0
//! Caller-bound discovery, projected from the same authorized surfaces as HTTP execution.

use super::*;
use crate::artifacts::{field_schema, field_value_schema};
use crate::contract::{ConstraintSource, ManifestProjectionSource, ManifestProjectionTextSource};
use crate::model::CompiledLogicalField;

/// Wrap authentication as well as handlers. Even refusals must not persist in an HTTP cache.
/// This changes only the cache policy, never held response bytes or replay headers.
pub(super) async fn no_store(request: axum::extract::Request, next: middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(super) fn operations(service: &HttpService, surfaces: &[AuthorizedSurface<'_>]) -> Vec<Value> {
    surfaces
        .iter()
        .map(|surface| operation(service, surface, surfaces))
        .collect()
}

fn operation(
    service: &HttpService,
    surface: &AuthorizedSurface<'_>,
    surfaces: &[AuthorizedSurface<'_>],
) -> Value {
    let profile = &surface.entity.access_profiles[surface.context.selected_profile()];
    let empty = BTreeSet::new();
    let create = if surface.route.operation == Operation::Create {
        &profile.writable_fields
    } else {
        &empty
    };
    let patch = if surface.route.operation == Operation::Patch {
        &profile.writable_fields
    } else {
        &empty
    };
    let fields = surface
        .readable_fields
        .iter()
        .chain(create)
        .chain(patch)
        .cloned()
        .collect::<BTreeSet<_>>();
    let query = surface
        .route
        .query_kind
        .and_then(|kind| query_operation_for_route(service, surface.route, surface, kind));
    let mut value = json!({
        "id": surface.route.id,
        "method": surface.route.method,
        "path": surface.route.path,
        "operation": surface.route.operation,
        "sourceEntity": surface.entity.id,
        "responseEntity": surface.response_entity.id,
        "accessProfile": surface.context.selected_profile(),
        "requiredCapabilities": required_capabilities(surface.route.operation),
        "entityLabel": entity_label(service, surface),
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": title_fields(service, surface),
        "fields": fields.iter().filter_map(|id| field(service, surface, surfaces, id, patch)).collect::<Vec<_>>(),
        "readableFields": surface.readable_fields,
        "createWritableFields": create,
        "patchWritableFields": patch,
        "selectors": selectors(service, surface),
        "query": query.map(|query| query_metadata(surface, query)),
        "request": request(surface, query),
    });
    if let Some(path) = surface.read_path {
        value["readPath"] = json!({"id": path.id, "label": humanize(&path.id)});
    }
    value
}

fn required_capabilities(operation: Operation) -> Vec<&'static str> {
    if matches!(
        operation,
        Operation::SubmitRequest
            | Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ReviseRequest
            | Operation::CancelRequest
            | Operation::ApplyRequest
    ) {
        vec!["change_request_lifecycle"]
    } else {
        Vec::new()
    }
}

fn field(
    service: &HttpService,
    surface: &AuthorizedSurface<'_>,
    surfaces: &[AuthorizedSurface<'_>],
    id: &str,
    patch: &BTreeSet<String>,
) -> Option<Value> {
    let entity = surface.response_entity;
    let logical = logical_field(entity, id)?;
    let stored = entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == id);
    let required = stored.is_some_and(|field| field.required);
    let mut value = json!({
        "id": id, "apiName": logical.api_name, "label": humanize(id),
        "schema": field_value_schema(&logical.field_type, !required),
        "required": required, "nullable": !required, "readOnly": stored.is_none(),
        "removable": patch.contains(id) && !required,
    });
    if let FieldTypeSource::Reference { target, .. } = &logical.field_type {
        let targets = surfaces
            .iter()
            .filter(|target_surface| {
                target_surface.entity.id == *target
                    && target_surface.read_path.is_none()
                    && target_surface.context.selected_profile()
                        == surface.context.selected_profile()
                    && matches!(
                        target_surface.route.operation,
                        Operation::Get | Operation::List | Operation::Lookup
                    )
            })
            .collect::<Vec<_>>();
        let mut reference = json!({
            "manualEntry": true,
            "operations": targets.iter().map(|target| json!({
                "operationId": target.route.id,
                "accessProfile": target.context.selected_profile(),
                "labelFields": title_fields(service, target),
            })).collect::<Vec<_>>(),
        });
        if !targets.is_empty() {
            reference["targetEntity"] = json!(target);
        }
        value["reference"] = reference;
    }
    if let FieldTypeSource::VocabularyCode { vocabulary, values } = &logical.field_type {
        let authored = projection(service, surface).and_then(|projection| {
            projection
                .vocabularies
                .iter()
                .find(|item| item.id == *vocabulary)
        });
        value["codeLabels"] = json!(values
            .iter()
            .map(|code| {
                let label = authored
                    .and_then(|vocabulary| {
                        vocabulary.concepts.iter().find(|item| item.code == *code)
                    })
                    .and_then(|concept| concept.label.as_ref())
                    .map(text_label)
                    .unwrap_or_else(|| humanize(code));
                (code.clone(), label)
            })
            .collect::<BTreeMap<_, _>>());
    }
    Some(value)
}

fn selectors(service: &HttpService, surface: &AuthorizedSurface<'_>) -> Vec<Value> {
    if surface.route.operation != Operation::Lookup {
        return Vec::new();
    }
    surface.entity.access_profiles[surface.context.selected_profile()].lookups.iter().filter_map(|grant| {
        let selector = surface.entity.selector_profiles.get(&grant.selector)?;
        lookup_query_operation_for_selector(service, surface.route, surface, &selector.id)?;
        let fields = selector.fields.iter().map(|id| {
            let field = logical_field(surface.entity, id)?;
            Some(json!({"id": id, "apiName": field.api_name, "label": humanize(id), "schema": field_schema(&field.field_type), "required": true}))
        }).collect::<Option<Vec<_>>>()?;
        let request_fields = if grant.value_origin == LookupValueOrigin::Request {
            fields.iter().map(|field| field["apiName"].clone()).collect::<Vec<_>>()
        } else { Vec::new() };
        Some(json!({"id": selector.id, "label": humanize(&selector.id), "valueOrigin": grant.value_origin, "fields": fields, "requestFields": request_fields}))
    }).collect()
}

fn query_metadata(surface: &AuthorizedSurface<'_>, query: &CompiledQueryOperation) -> Value {
    let entity = surface.response_entity;
    json!({
        "kind": query.kind,
        "selectableFields": query.projection_fields.iter().filter(|id| surface.readable_fields.contains(*id)).filter_map(|id| field_identity(entity, id)).collect::<Vec<_>>(),
        "filterableFields": query.filter_fields.iter().filter_map(|field| {
            let mut value = field_identity(entity, &field.field)?;
            value["operators"] = json!(field.operators);
            Some(value)
        }).collect::<Vec<_>>(),
        "sortableFields": query.sort_fields.iter().filter_map(|field| {
            let mut value = field_identity(entity, &field.field)?;
            value["directions"] = json!(field.directions);
            Some(value)
        }).collect::<Vec<_>>(),
        "allowCount": query.allow_count,
        "defaultPageSize": query.max_page_size,
        "maxPageSize": query.max_page_size,
        "maxFilterClauses": MAX_FILTER_CLAUSES,
        "maxInValues": MAX_IN_VALUES,
        "pagination": {"parameter": "$skiptoken", "responsePath": "pageInfo.nextCursor", "exclusive": true},
        "temporal": match query.kind {
            CompiledQueryKind::List => Value::Null,
            CompiledQueryKind::Current => json!({"mode": "current"}),
            CompiledQueryKind::AsOf => json!({"mode": "as_of", "parameter": "asOf", "required": true, "schema": {"type": "string", "format": "date-time"}}),
        },
    })
}

fn request(surface: &AuthorizedSurface<'_>, query: Option<&CompiledQueryOperation>) -> Value {
    let mut parameters = Vec::new();
    if matches!(surface.route.operation, Operation::Get | Operation::Lookup) || query.is_some() {
        parameters.push("$select");
    }
    if let Some(query) = query {
        parameters.extend(["$top", "$skiptoken"]);
        if !query.filter_fields.is_empty() {
            parameters.push("$filter");
        }
        if !query.sort_fields.is_empty() {
            parameters.push("$orderby");
        }
        if query.allow_count {
            parameters.push("$count");
        }
        if query.kind == CompiledQueryKind::AsOf {
            parameters.push("asOf");
        }
    }
    parameters.sort_unstable();
    let mut value = json!({"fieldNames": "api", "queryParameters": parameters});
    match surface.route.operation {
        Operation::Create => {
            value["body"] = json!("data_envelope");
            value["contentType"] = json!("application/json");
            value["idempotencyKeyRequired"] = json!(true);
            value["mutationSemantics"] = json!("direct");
            value["schema"] = json!({"type": "object", "additionalProperties": false, "required": ["data"], "properties": {
                "data": crate::artifacts::openapi_entity_input_schema(surface.entity, Some(&surface.entity.access_profiles[surface.context.selected_profile()].writable_fields))
            }});
        }
        Operation::Patch => {
            value["body"] = json!("json_patch");
            value["contentType"] = json!("application/json-patch+json");
            value["patchPathPrefix"] = json!("/data/");
            value["patchOperations"] = json!(["add", "replace", "remove", "test"]);
            value["removeSemantics"] = json!("set_null");
            value["ifMatchRequired"] = json!(true);
            value["idempotencyKeyRequired"] = json!(true);
            value["mutationSemantics"] = json!("direct");
            value["schema"] = crate::artifacts::json_patch_array_schema();
        }
        Operation::Lookup => {
            value["body"] = json!("selector_values");
            value["contentType"] = json!("application/json");
        }
        _ => {}
    }
    value
}

fn logical_field<'a>(entity: &'a CompiledEntity, id: &str) -> Option<&'a CompiledLogicalField> {
    entity
        .stored_fields
        .iter()
        .map(|field| &field.logical)
        .chain(entity.derived_fields.values().map(|field| &field.logical))
        .find(|field| field.id == id)
}

fn field_identity(entity: &CompiledEntity, id: &str) -> Option<Value> {
    let field = if id == entity.canonical_id.id {
        &entity.canonical_id
    } else {
        logical_field(entity, id)?
    };
    Some(json!({"id": id, "apiName": field.api_name}))
}

fn projection<'a>(
    service: &'a HttpService,
    surface: &AuthorizedSurface<'_>,
) -> Option<&'a ManifestProjectionSource> {
    service
        .registry
        .manifest_projection()
        .filter(|projection| projection.access_profile == surface.context.selected_profile())
}

fn title_fields(service: &HttpService, surface: &AuthorizedSurface<'_>) -> Vec<String> {
    let authored = projection(service, surface)
        .and_then(|projection| {
            projection
                .entities
                .iter()
                .find(|entity| entity.id == surface.response_entity.id)
        })
        .and_then(|entity| {
            entity
                .identifiers
                .iter()
                .find(|identifier| readable_string(surface, &identifier.field))
        })
        .map(|identifier| identifier.field.clone());
    authored
        .or_else(|| temporal_scope_title_field(surface))
        .or_else(|| unique_title_field(surface))
        .or_else(|| {
            surface
                .readable_fields
                .iter()
                .find(|id| readable_string(surface, id))
                .cloned()
        })
        .into_iter()
        .collect()
}

fn readable_string(surface: &AuthorizedSurface<'_>, id: &str) -> bool {
    surface.readable_fields.contains(id)
        && logical_field(surface.response_entity, id)
            .is_some_and(|field| matches!(field.field_type, FieldTypeSource::String { .. }))
}

fn readable_text_or_string(surface: &AuthorizedSurface<'_>, id: &str) -> bool {
    surface.readable_fields.contains(id)
        && logical_field(surface.response_entity, id).is_some_and(|field| {
            matches!(
                field.field_type,
                FieldTypeSource::String { .. } | FieldTypeSource::Text { .. }
            )
        })
}

fn temporal_scope_title_field(surface: &AuthorizedSurface<'_>) -> Option<String> {
    let temporal = surface.response_entity.temporal.as_ref()?;
    let [field] = temporal.scope_fields.as_slice() else {
        return None;
    };
    readable_text_or_string(surface, field).then(|| field.clone())
}

fn unique_title_field(surface: &AuthorizedSurface<'_>) -> Option<String> {
    surface
        .response_entity
        .constraints
        .values()
        .find_map(|constraint| {
            let ConstraintSource::Unique {
                fields, when: None, ..
            } = constraint
            else {
                return None;
            };
            let [field] = fields.as_slice() else {
                return None;
            };
            readable_text_or_string(surface, field).then(|| field.clone())
        })
}

fn entity_label(service: &HttpService, surface: &AuthorizedSurface<'_>) -> String {
    projection(service, surface)
        .and_then(|projection| {
            projection
                .entities
                .iter()
                .find(|entity| entity.id == surface.response_entity.id)
        })
        .and_then(|entity| entity.title.as_ref())
        .map(text_label)
        .unwrap_or_else(|| humanize(&surface.response_entity.id))
}

fn text_label(text: &ManifestProjectionTextSource) -> String {
    match text {
        ManifestProjectionTextSource::Plain(text) => text.clone(),
        ManifestProjectionTextSource::Localized(labels) => {
            labels.values().next().cloned().unwrap_or_default()
        }
    }
}

fn humanize(id: &str) -> String {
    let words = id.replace(['-', '_'], " ");
    let mut chars = words.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_lifecycle_operations_require_an_explicit_workspace_capability() {
        for operation in [
            Operation::SubmitRequest,
            Operation::ApproveRequest,
            Operation::RejectRequest,
            Operation::RequestRevision,
            Operation::ReviseRequest,
            Operation::CancelRequest,
            Operation::ApplyRequest,
        ] {
            assert_eq!(
                required_capabilities(operation),
                ["change_request_lifecycle"]
            );
        }
        assert!(required_capabilities(Operation::Create).is_empty());
        assert!(required_capabilities(Operation::Patch).is_empty());
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Caller-bound discovery, projected from the same authorized surfaces as HTTP execution.

use super::*;
use crate::artifacts::{field_schema, field_value_schema};
use crate::contract::{ConstraintSource, ManifestProjectionTextSource};
use crate::model::CompiledLogicalField;
use crate::model::CompiledManifestProjection;

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
    let create = if surface.route.operation == Operation::Create
        || (surface.route.operation == Operation::Batch
            && profile.operations.contains(&Operation::Create))
    {
        &profile.writable_fields
    } else {
        &empty
    };
    let patch = if surface.route.operation == Operation::Patch
        || (surface.route.operation == Operation::Batch
            && profile.operations.contains(&Operation::Patch))
    {
        &profile.writable_fields
    } else {
        &empty
    };
    let create = create.clone();
    let patch = patch.clone();
    let fields = surface
        .readable_fields
        .iter()
        .chain(&create)
        .chain(&patch)
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
        "sourceRecordType": surface.entity.id,
        "responseRecordType": surface.response_entity.id,
        "accessProfile": surface.context.selected_profile(),
        "requiredCapabilities": required_capabilities(surface.route.operation),
        "recordTypeLabel": entity_label(service, surface),
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": title_fields(service, surface),
        "fields": fields.iter().filter_map(|id| field(service, surface, surfaces, id, &patch)).collect::<Vec<_>>(),
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

fn required_capabilities(_operation: Operation) -> Vec<&'static str> {
    Vec::new()
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
    let display = entity.fields.get(id).map(|field| &field.display);
    let label = display
        .and_then(|display| display.label.clone())
        .unwrap_or_else(|| humanize(id));
    let mut schema = field_value_schema(&logical.field_type, !required);
    if let Some(description) = display.and_then(|display| display.description.as_ref()) {
        schema["description"] = json!(description);
    }
    let mut value = json!({
        "id": id, "apiName": logical.api_name, "label": label,
        "schema": schema,
        "required": required, "nullable": !required, "readOnly": stored.is_none(),
        "removable": patch.contains(id) && !required,
    });
    if let Some(pattern) = entity
        .fields
        .get(id)
        .and_then(|field| field.pattern.as_ref())
    {
        value["storageValidation"] = json!({
            "kind": "postgresql-are", "pattern": pattern,
        });
    }
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
            reference["targetRecordType"] = json!(target);
            if let Some(relationship) = entity.relationships.get(&logical.api_name) {
                reference["name"] = json!(relationship.name);
                reference["cardinality"] = json!(relationship.cardinality);
                if let Some(inverse) = &relationship.inverse_name {
                    reference["inverseName"] = json!(inverse);
                }
            }
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
    let selectable_fields = query
        .projection_fields
        .iter()
        .filter(|id| surface.readable_fields.contains(*id))
        .collect::<BTreeSet<_>>();
    let mut value = json!({
        "kind": query.kind,
        "selectableFields": selectable_fields.into_iter().filter_map(|id| field_identity(entity, id)).collect::<Vec<_>>(),
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
        "maximumPageSize": query.max_page_size,
        "maximumFilterClauses": MAX_FILTER_CLAUSES,
        "maximumInValues": MAX_IN_VALUES,
        "pagination": {"parameter": "$skiptoken", "responsePath": "pageInfo.nextCursor", "exclusive": true},
        "temporal": temporal_metadata(query),
    });
    if let Some(bbox) = query
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
    {
        value["spatialQueries"] = json!({"bbox": {
            "geometryProperty": field_identity(entity, &bbox.geometry_field)
                .and_then(|field| field.get("apiName").cloned())
                .unwrap_or_else(|| json!(bbox.geometry_field)),
            "maximumLongitudeSpanDegrees": bbox.maximum_longitude_span_degrees,
            "maximumLatitudeSpanDegrees": bbox.maximum_latitude_span_degrees,
            "coordinateReferenceSystem": "CRS84",
            "semantics": "inclusive_2d_non_crossing",
        }});
    }
    value
}

fn temporal_metadata(query: &CompiledQueryOperation) -> Value {
    match query.kind {
        CompiledQueryKind::List => Value::Null,
        CompiledQueryKind::Current => json!({"mode": "current"}),
        CompiledQueryKind::AsOf => {
            json!({"mode": "as-of", "parameter": "asOf", "required": true, "schema": {"type": "string", "format": "date-time"}})
        }
        CompiledQueryKind::Snapshot => {
            let mut value = json!({
                "mode": "snapshot",
                "snapshot": {
                    "parameter": "snapshot",
                    "required": false,
                    "schema": {"type": "string", "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES},
                },
            });
            if let Some(temporal) = &query.temporal {
                let schema = match temporal.value_kind {
                    crate::model::CompiledQueryTemporalValueKind::Date => {
                        json!({"type": "string", "format": "date"})
                    }
                    crate::model::CompiledQueryTemporalValueKind::Timestamp => {
                        json!({"type": "string", "format": "date-time"})
                    }
                };
                value["validAt"] = json!({
                    "parameter": "validAt",
                    "required": false,
                    "schema": schema,
                });
            }
            value
        }
    }
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
        if query.kind == CompiledQueryKind::Snapshot {
            parameters.push("snapshot");
            if query.temporal.is_some() {
                parameters.push("validAt");
            }
        }
        if query
            .spatial
            .as_ref()
            .and_then(|spatial| spatial.bbox.as_ref())
            .is_some()
        {
            parameters.push("bbox");
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
        Operation::Tombstone => {
            value["body"] = json!("none");
            value["ifMatchRequired"] = json!(true);
            value["idempotencyKeyRequired"] = json!(true);
            value["mutationSemantics"] = json!("direct");
        }
        Operation::Batch => {
            let profile = &surface.entity.access_profiles[surface.context.selected_profile()];
            let batch = surface
                .entity
                .batch
                .as_ref()
                .expect("served batch routes have compiled bounds");
            value["body"] = json!("batch");
            value["contentType"] = json!("application/json");
            value["idempotencyKeyRequired"] = json!(true);
            value["mutationSemantics"] = json!("direct");
            value["maximumItems"] = json!(batch.maximum_items);
            value["maximumBodyBytes"] = json!(batch.maximum_bytes);
            value["allowCreate"] = json!(profile.operations.contains(&Operation::Create));
            value["allowPatch"] = json!(profile.operations.contains(&Operation::Patch));
            value["schema"] = crate::artifacts::openapi_batch_input_schema(
                surface.entity,
                Some(&profile_batch_writable_fields(surface)),
                batch.maximum_items,
                profile.operations.contains(&Operation::Create),
                profile.operations.contains(&Operation::Patch),
            );
        }
        Operation::Lookup => {
            value["body"] = json!("selector_values");
            value["contentType"] = json!("application/json");
        }
        _ => {}
    }
    value
}

fn profile_batch_writable_fields(surface: &AuthorizedSurface<'_>) -> BTreeSet<String> {
    surface.entity.access_profiles[surface.context.selected_profile()]
        .writable_fields
        .iter()
        .cloned()
        .collect()
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
) -> Option<&'a CompiledManifestProjection> {
    service
        .registry
        .manifest_projection()
        .filter(|projection| projection.access_profile == surface.context.selected_profile())
}

fn title_fields(service: &HttpService, surface: &AuthorizedSurface<'_>) -> Vec<String> {
    if let Some(field) = &surface.response_entity.display.title_field {
        return readable_text_or_string(surface, field)
            .then(|| field.clone())
            .into_iter()
            .collect();
    }
    let native = surface
        .response_entity
        .display
        .title_field
        .as_ref()
        .filter(|field| readable_text_or_string(surface, field))
        .cloned();
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
    native
        .or(authored)
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
    let fields = surface
        .response_entity
        .constraints
        .values()
        .filter_map(|constraint| {
            let ConstraintSource::TemporalNonOverlap {
                scope_fields,
                start_field,
                end_field,
                ..
            } = constraint
            else {
                return None;
            };
            if start_field
                .as_deref()
                .is_some_and(|field| field != temporal.start_field)
                || end_field
                    .as_deref()
                    .is_some_and(|field| field != temporal.end_field)
            {
                return None;
            }
            let [field] = scope_fields.as_slice() else {
                return None;
            };
            readable_text_or_string(surface, field).then_some(field)
        })
        .collect::<BTreeSet<_>>();
    let mut fields = fields.into_iter();
    let field = fields.next()?;
    fields.next().is_none().then(|| field.clone())
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
    surface
        .response_entity
        .display
        .label
        .clone()
        .or_else(|| {
            projection(service, surface)
                .and_then(|projection| {
                    projection
                        .entities
                        .iter()
                        .find(|entity| entity.id == surface.response_entity.id)
                })
                .and_then(|entity| entity.title.as_ref())
                .map(text_label)
        })
        .unwrap_or_else(|| humanize(&surface.response_entity.id))
}

fn text_label(text: &ManifestProjectionTextSource) -> String {
    match text {
        ManifestProjectionTextSource::Plain(text) => text.as_str().to_owned(),
        ManifestProjectionTextSource::Localized(labels) => labels
            .values()
            .next()
            .map(|text| text.as_str().to_owned())
            .unwrap_or_default(),
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
    fn record_operations_do_not_require_retired_lifecycle_capabilities() {
        assert!(required_capabilities(Operation::Create).is_empty());
        assert!(required_capabilities(Operation::Patch).is_empty());
    }

    #[test]
    fn proposal_apply_schema_binds_the_frozen_submission() {
        let decision = crate::artifacts::proposal_apply_input_schema();
        assert_eq!(
            decision["required"],
            json!(["submissionVersion", "effectDigest"])
        );
        assert_eq!(
            decision["properties"]["effectDigest"]["pattern"],
            "^sha256:[0-9a-f]{64}$"
        );
    }
}

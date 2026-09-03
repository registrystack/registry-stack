// SPDX-License-Identifier: Apache-2.0
//! HTTP surface compiled from one immutable Registry inventory.

mod actions;
#[cfg(test)]
#[path = "tests/change_request_action_tests.rs"]
mod change_request_action_tests;
#[cfg(test)]
#[path = "tests/change_request_read_tests.rs"]
mod change_request_read_tests;
mod context;
mod gis;
mod metadata;
mod service;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MATCH, LINK, VARY};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{middleware, Extension, Json, Router};
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httpsec::{security_headers, CspBuilder};
use serde_json::{json, Map, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) use context::VerifiedRequestActionAuthority;
pub use context::{
    AuthorizedActionContext, AuthorizedRequestContext, RowBoundaryOperator, VerifiedClaimValue,
    VerifiedContextError, VerifiedRequestAction, VerifiedRequestClaims, VerifiedRequestPresence,
    VerifiedRequestTargetAuthority, VerifiedRowBoundary,
};
pub(crate) use service::{cursor_query_reference_value, CursorQueryReferenceInput};
pub use service::{
    ActionTargetConditionsInput, BatchMutationInput, CompiledLookupSelector, CompiledReadQuery,
    ConditionalMutationInput, CreateMutationInput, HeldReadResponse, HttpService,
    ImmediateActionInput, LookupSelectorValue, ReadBboxQuery, ReadFilterExpr, ReadFilterOperator,
    ReadFilterPredicate, ReadLogicalOp, ReadOrderClause, ReadProjectionField, ReadRuntimeIdentity,
    ReadServiceError, ReadSpatialQuery, ReadinessProbe, RecordReadKind, RecordReadRefusal,
    RecordReadRequest, RecordReadService, RequestActionBody, RequestActionInput,
    RequestActionTargetAuthority, RevisionReadRefusal, RevisionReadRequest, RevisionReadService,
    ServiceFuture, SnapshotReadRequest, SnapshotReadService,
};

use crate::auth::{authenticate_request, RegistryAuthenticator};
use crate::contract::{
    AccessProfileSource, BoundaryOperator, Classification, FieldTypeSource, LookupValueOrigin,
    Operation, RowBoundarySource,
};
use crate::correlation::RequestCorrelation;
use crate::cursor::{
    now_unix_seconds, CursorAdapter, CursorBboxQuery, CursorBinding, CursorError, CursorFilterExpr,
    CursorFilterOperator, CursorFilterPredicate, CursorLogicalOp, CursorOrderClause,
    CursorProjectionField, CursorQueryScope, CursorRepresentation, CursorSpatialQuery,
};
use crate::idempotency::{HeldResponse, PermittedResponseHeader};
use crate::metrics::{AnonymousRefusal, AnonymousRefusalReason};
use crate::model::{
    request_query_field_id_for_api, request_query_field_type, CompiledChangeRequest,
    CompiledChangeRequestApplicationMode, CompiledChangeRequestDisposition,
    CompiledChangeRequestReviewMode, CompiledEntity, CompiledMetadataEntity, CompiledMetadataEntry,
    CompiledQueryKind, CompiledQueryOperation, CompiledQuerySortDirection, CompiledReadPath,
    CompiledRevisionKind, CompiledRoute, MAX_REVISION_HISTORY_RECORDS,
};
use crate::mutation::{parse_json_patch_document, BatchMutationItem, MutationError};
use crate::query as strict_query;
use crate::query_binding::CursorBindingQuery;
use crate::record_profile::{self, RecordRepresentation};
use uuid::Uuid;

use crate::artifacts::{
    openapi_components, openapi_entity_input_schema, openapi_input_schema_id, openapi_operation,
    openapi_request_action_input_schema, OpenApiAccessProfiles, OpenApiOperationSpec,
};

const MAX_MUTATION_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOOKUP_BODY_BYTES: usize = 16 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_RAW_QUERY_BYTES: usize = 16 * 1024;
const MAX_FILTER_CLAUSES: usize = 32;
const MAX_IN_VALUES: usize = 100;

/// Construct the low-level route set for callers that already hold verified
/// claims. Production network listeners must use [`authenticated_router`].
///
/// This seam preserves focused authorization and record-kernel tests without
/// allowing request headers or query values to construct authority.
pub fn router(service: Arc<HttpService>) -> Router {
    route_set(service)
        .layer(middleware::from_fn(metadata::no_store))
        .layer(middleware::from_fn(crate::correlation::observe))
        .layer(security_headers(CspBuilder::restrictive()))
}

fn route_set(service: Arc<HttpService>) -> Router {
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/ready", get(ready))
        .route("/openapi.json", get(openapi))
        .route("/v1/registry", get(registry_metadata))
        .route("/v1/schemas/{entity_id}", get(entity_schema));

    for route in &service.registry.routes().routes {
        app = match route.operation {
            Operation::Get | Operation::List => app.route(
                &route.path,
                get(read_dispatch).layer(Extension(route.clone())),
            ),
            Operation::Lookup => app.route(
                &route.path,
                post(lookup_dispatch).layer(Extension(route.clone())),
            ),
            Operation::Revisions if service.revisions.is_some() => app.route(
                &route.path,
                get(revision_dispatch).layer(Extension(route.clone())),
            ),
            Operation::Snapshot if service.snapshots.is_some() => app.route(
                &route.path,
                get(snapshot_dispatch).layer(Extension(route.clone())),
            ),
            Operation::Create if service.mutations.is_some() => app.route(
                &route.path,
                post(create_dispatch).layer(Extension(route.clone())),
            ),
            Operation::Batch if service.mutations.is_some() => app.route(
                &route.path,
                post(batch_dispatch).layer(Extension(route.clone())),
            ),
            Operation::Patch
                if service.mutations.is_some()
                    && service
                        .registry
                        .entities()
                        .get(&route.entity_id)
                        .is_some_and(|entity| {
                            entity.mutation_mode == crate::contract::MutationMode::Mutable
                        }) =>
            {
                app.route(
                    &route.path,
                    patch(patch_dispatch).layer(Extension(route.clone())),
                )
            }
            Operation::Tombstone
                if service.mutations.is_some()
                    && service
                        .registry
                        .entities()
                        .get(&route.entity_id)
                        .is_some_and(|entity| {
                            entity.mutation_mode == crate::contract::MutationMode::Mutable
                                && entity.tombstone
                        }) =>
            {
                app.route(
                    &route.path,
                    delete(tombstone_dispatch).layer(Extension(route.clone())),
                )
            }
            Operation::SubmitRequest
            | Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ReviseRequest
            | Operation::CancelRequest
            | Operation::ApplyRequest
                if service.mutations.is_some()
                    && service
                        .registry
                        .entities()
                        .get(&route.entity_id)
                        .is_some_and(|entity| entity.change_request.is_some()) =>
            {
                app.route(
                    &route.path,
                    post(request_action_dispatch).layer(Extension(route.clone())),
                )
            }
            _ => app,
        };
    }

    if service.mutations.is_some() {
        for route in &service.registry.actions().routes {
            app = app.route(
                &route.path,
                post(actions::dispatch).layer(Extension(route.clone())),
            );
        }
    }

    app.merge(gis::routes())
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .with_state(service)
}

/// Construct the production network router. Bearer admission and complete
/// configured OIDC verification wrap every route, including anonymous and
/// discovery surfaces, so an invalid presented credential never downgrades to
/// anonymous access.
pub fn authenticated_router(
    service: Arc<HttpService>,
    authenticator: Arc<RegistryAuthenticator>,
) -> Router {
    route_set(service)
        .layer(middleware::from_fn_with_state(
            authenticator,
            authenticate_request,
        ))
        .layer(middleware::from_fn(metadata::no_store))
        .layer(middleware::from_fn(crate::correlation::observe))
        .layer(security_headers(CspBuilder::restrictive()))
}

async fn health() -> Response {
    Json(json!({"status": "alive"})).into_response()
}

async fn ready(State(service): State<Arc<HttpService>>) -> Response {
    if service.readiness.is_ready().await {
        Json(json!({"status": "ready"})).into_response()
    } else {
        fixed_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime.not_ready",
            "Registry runtime is not ready.",
        )
    }
}

async fn openapi(
    State(service): State<Arc<HttpService>>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let visible = visible_surfaces(&service, &claims, &options);
    let visible_actions = actions::visible_actions(&service, &claims, &options);
    if visible.is_empty() && visible_actions.is_empty() {
        return concealed();
    }

    let mut paths = Map::new();
    let mut readable_by_entity: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut writable_by_input_schema: BTreeMap<String, (String, BTreeSet<String>)> =
        BTreeMap::new();
    let mut action_input_schemas = Map::new();
    for surface in &visible {
        let path = paths
            .entry(surface.route.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(methods) = path else {
            unreachable!("OpenAPI paths are objects")
        };
        let request_schema_ref =
            openapi_input_schema_id(&surface.entity.id, surface.route.operation);
        methods.insert(
            method_name(surface.route.method).to_owned(),
            openapi_operation(OpenApiOperationSpec {
                registry_identifier: service.registry.registry_id(),
                route: surface.route,
                entity: surface.entity,
                response_entity: surface.response_entity,
                query: service.registry.queries(),
                schema_ref: &surface.response_entity.id,
                request_schema_ref: &request_schema_ref,
                readable_fields: Some(&surface.readable_fields),
                access_profiles: OpenApiAccessProfiles::Selected(
                    surface.context.selected_profile(),
                ),
            }),
        );
        readable_by_entity
            .entry(surface.response_entity.id.clone())
            .and_modify(|fields| {
                fields.extend(surface.readable_fields.iter().cloned());
            })
            .or_insert_with(|| surface.readable_fields.clone());
        if matches!(
            surface.route.operation,
            Operation::Create | Operation::Batch
        ) {
            let profile = &surface.entity.access_profiles[surface.context.selected_profile()];
            let entry = writable_by_input_schema
                .entry(request_schema_ref)
                .or_insert_with(|| (surface.entity.id.clone(), BTreeSet::new()));
            entry.1.extend(profile.writable_fields.iter().cloned());
        } else if is_request_operation(surface.route.operation) {
            action_input_schemas.insert(
                request_schema_ref,
                openapi_request_action_input_schema(surface.route.operation),
            );
        }
    }

    let mut schemas = readable_by_entity
        .iter()
        .filter_map(|(entity_id, readable)| {
            filtered_schema(
                &service,
                entity_id,
                readable,
                &permitted_request_types(&visible),
            )
            .map(|schema| (entity_id.clone(), schema))
        })
        .collect::<Map<String, Value>>();
    schemas.extend(writable_by_input_schema.iter().filter_map(
        |(schema_id, (entity_id, writable))| {
            service.registry.entities().get(entity_id).map(|entity| {
                (
                    schema_id.clone(),
                    openapi_entity_input_schema(entity, Some(writable)),
                )
            })
        },
    ));
    let has_request_actions = !action_input_schemas.is_empty();
    schemas.extend(action_input_schemas);
    actions::append_openapi(&visible_actions, &mut paths, &mut schemas);
    Json(json!({
        "openapi": "3.1.0",
        "info": {"title": service.registry.registry_id(), "version": service.registry.version()},
        "paths": paths,
        "components": openapi_components(schemas, has_request_actions, !visible_actions.is_empty())
    }))
    .into_response()
}

async fn registry_metadata(
    State(service): State<Arc<HttpService>>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let surfaces = visible_surfaces(&service, &claims, &options);
    let operations = metadata::operations(&service, &surfaces);
    let visible = visible_metadata_entries(&service, &claims, &options);
    let visible_actions = actions::visible_actions(&service, &claims, &options);
    if visible.is_empty() && visible_actions.is_empty() {
        return concealed();
    }

    let mut entities: BTreeMap<String, MetadataEntity> = BTreeMap::new();
    let permitted_requests =
        permitted_request_types(&visible_surfaces(&service, &claims, &options));
    for (_, entry) in visible {
        let Some(response_entity) = service.registry.entities().get(&entry.response_entity_id)
        else {
            return concealed();
        };
        let Some(dataset_identifier) = response_entity.primary_dataset.as_ref() else {
            return concealed();
        };
        entities
            .entry(response_entity.id.clone())
            .and_modify(|metadata| {
                metadata
                    .operations
                    .insert(entry.operation, entry.access_profile.clone());
                metadata
                    .readable_fields
                    .extend(entry.readable_fields.iter().cloned());
            })
            .or_insert_with(|| MetadataEntity {
                id: response_entity.id.clone(),
                dataset_identifier: dataset_identifier.clone(),
                route: response_entity.route.clone(),
                operations: BTreeMap::from([(entry.operation, entry.access_profile.clone())]),
                readable_fields: entry.readable_fields.clone(),
                schema_path: format!("/v1/schemas/{}", response_entity.id),
                change_control: response_entity.change_control.as_ref().map(|_| {
                    metadata_change_control(&service, response_entity, &permitted_requests)
                }),
                change_request: response_entity.change_request.as_ref().map(|request| {
                    crate::artifacts::request_capability_metadata(request, &entry.readable_fields)
                }),
            });
    }
    let entities = entities
        .into_values()
        .map(|entity| {
            let mut metadata = json!({
                "id": entity.id,
                "datasetIdentifier": entity.dataset_identifier,
                "route": entity.route,
                "operations": entity.operations.into_iter().map(|(operation, access_profile)| json!({
                    "operation": operation_name(operation),
                    "accessProfile": access_profile,
                })).collect::<Vec<_>>(),
                "readableFields": entity.readable_fields,
                "schema": entity.schema_path,
            });
            if let Some(change_control) = entity.change_control {
                metadata["changeControl"] = change_control;
            }
            if let Some(change_request) = entity.change_request {
                metadata["changeRequest"] = change_request;
            }
            metadata
        })
        .collect::<Vec<_>>();
    let mut metadata = json!({
        "id": service.registry.registry_id(),
        "version": service.registry.version(),
        "revision": service.registry.revision(),
        "entities": entities,
        "metadataVersion": "1",
        "operations": operations,
    });
    // Preserve action-free discovery output while omitting unavailable actions.
    if !visible_actions.is_empty() {
        metadata["actions"] = actions::metadata(&visible_actions);
    }
    Json(metadata).into_response()
}

async fn entity_schema(
    State(service): State<Arc<HttpService>>,
    Path(entity_id): Path<String>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let surfaces = visible_surfaces(&service, &claims, &options)
        .into_iter()
        .filter(|surface| surface.response_entity.id == entity_id)
        .collect::<Vec<_>>();
    let Some(first) = surfaces.first() else {
        return concealed();
    };
    let readable =
        surfaces
            .iter()
            .skip(1)
            .fold(first.readable_fields.clone(), |mut fields, surface| {
                fields.extend(surface.readable_fields.iter().cloned());
                fields
            });
    let permitted_requests =
        permitted_request_types(&visible_surfaces(&service, &claims, &options));
    match filtered_schema(&service, &entity_id, &readable, &permitted_requests) {
        Some(schema) => Json(schema).into_response(),
        None => concealed(),
    }
}

async fn read_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let options = match QueryOptions::parse(raw_query.as_deref(), true) {
        Ok(options) => options,
        Err(QueryParseError::Invalid) => {
            return audited_known_read_refusal(
                &service,
                &route,
                &claims,
                path.get("record_id"),
                invalid_query(),
                &correlation,
            )
            .await;
        }
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        let response = audited_read_concealment(
            &service,
            &route,
            &options,
            &claims,
            path.get("record_id"),
            &correlation,
        )
        .await;
        return response;
    };
    let representation = negotiated_read_representation(&headers);

    if options.request_history_after_proposal_version.is_some()
        && (route.operation != Operation::Get || surface.entity.change_request.is_none())
    {
        return audited_read_refusal(
            &service,
            &route,
            &surface,
            path.get("record_id"),
            invalid_query(),
            &correlation,
        )
        .await;
    }
    match route.operation {
        Operation::Get => {
            if surface.read_path.is_some() || options.has_non_history_query_members() {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    path.get("record_id"),
                    invalid_query(),
                    &correlation,
                )
                .await;
            }
            let Some(record_id) = path.get("record_id") else {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    None,
                    concealed(),
                    &correlation,
                )
                .await;
            };
            if !valid_canonical_record_uuid(record_id) {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    Some(record_id),
                    concealed(),
                    &correlation,
                )
                .await;
            }
            let readable_fields = match resolve_select(
                surface.response_entity,
                &surface.readable_fields,
                options.select_clause(),
            ) {
                Ok(Some(fields)) => fields,
                Ok(None) => surface.readable_fields.clone(),
                Err(()) => {
                    return audited_read_refusal(
                        &service,
                        &route,
                        &surface,
                        Some(record_id),
                        concealed(),
                        &correlation,
                    )
                    .await;
                }
            };
            if representation == CursorRepresentation::GeoJson && !geojson_available(&surface) {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    Some(record_id),
                    concealed(),
                    &correlation,
                )
                .await;
            }
            let request = RecordReadRequest {
                entity_id: route.entity_id.clone(),
                operation_id: route.id.clone(),
                method: route.method,
                context: surface.context,
                selected_fields: readable_fields,
                representation,
                adapter: CursorAdapter::Native,
                adapter_origin: None,
                geojson_next_link_prefix: None,
                kind: RecordReadKind::Get {
                    id: record_id.clone(),
                },
                maximum_records: 1,
                request_history_after_proposal_version: options
                    .request_history_after_proposal_version,
                correlation: correlation.clone(),
            };
            match service.records.get(request).await {
                Ok(Some(record)) => exact_read(record, surface.response_entity),
                Ok(None) => concealed(),
                Err(ReadServiceError::Unavailable) => unavailable(),
                Err(ReadServiceError::CursorInvalid) => cursor_invalid(),
            }
        }
        Operation::List => {
            if surface.read_path.is_some()
                && !path
                    .get("record_id")
                    .is_some_and(|record_id| valid_canonical_record_uuid(record_id))
            {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    path.get("record_id"),
                    concealed(),
                    &correlation,
                )
                .await;
            }
            let query = match read_query(
                &service,
                &route,
                &surface,
                &options,
                path.get("record_id").map(String::as_str),
                representation,
                CursorAdapter::Native,
            )
            .await
            {
                Ok(Some(query)) => query,
                Ok(None) => return unavailable(),
                Err(ReadQueryError::Invalid) => {
                    return audited_read_refusal(
                        &service,
                        &route,
                        &surface,
                        path.get("record_id"),
                        invalid_query(),
                        &correlation,
                    )
                    .await;
                }
                Err(ReadQueryError::CursorInvalid) => {
                    return audited_read_refusal(
                        &service,
                        &route,
                        &surface,
                        path.get("record_id"),
                        cursor_invalid(),
                        &correlation,
                    )
                    .await;
                }
            };
            let readable_fields = query
                .cursor_binding
                .selected_fields
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if !readable_fields.is_subset(&surface.readable_fields) {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    path.get("record_id"),
                    concealed(),
                    &correlation,
                )
                .await;
            }
            if representation == CursorRepresentation::GeoJson && !geojson_available(&surface) {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    path.get("record_id"),
                    concealed(),
                    &correlation,
                )
                .await;
            }
            let maximum_records = usize::from(query.page_size) + 1;
            let kind = if let Some(read_path) = surface.read_path {
                RecordReadKind::Relationship {
                    root_id: path
                        .get("record_id")
                        .expect("relationship root id was validated")
                        .clone(),
                    path_id: read_path.id.clone(),
                    plan: query,
                }
            } else {
                RecordReadKind::List { plan: query }
            };
            let request = RecordReadRequest {
                entity_id: route.entity_id.clone(),
                operation_id: route.id.clone(),
                method: route.method,
                context: surface.context,
                selected_fields: readable_fields,
                representation,
                adapter: CursorAdapter::Native,
                adapter_origin: None,
                geojson_next_link_prefix: None,
                kind,
                maximum_records,
                request_history_after_proposal_version: None,
                correlation: correlation.clone(),
            };
            match service.records.list(request).await {
                Ok(response) => exact_read_no_store(response, surface.response_entity),
                Err(ReadServiceError::Unavailable) => unavailable(),
                Err(ReadServiceError::CursorInvalid) => cursor_invalid(),
            }
        }
        _ => concealed(),
    }
}

async fn lookup_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let options = match QueryOptions::parse(raw_query.as_deref(), true) {
        Ok(options) => options,
        Err(QueryParseError::Invalid) => {
            return audited_known_read_refusal(
                &service,
                &route,
                &claims,
                None,
                invalid_query(),
                &correlation,
            )
            .await;
        }
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_read_concealment(&service, &route, &options, &claims, None, &correlation)
            .await;
    };
    if surface.read_path.is_some() || options.has_non_projection_query_members() {
        return audited_read_refusal(
            &service,
            &route,
            &surface,
            None,
            invalid_query(),
            &correlation,
        )
        .await;
    }
    let readable_fields = match resolve_select(
        surface.response_entity,
        &surface.readable_fields,
        options.select_clause(),
    ) {
        Ok(Some(fields)) => fields,
        Ok(None) => surface.readable_fields.clone(),
        Err(()) => {
            return audited_read_refusal(
                &service,
                &route,
                &surface,
                None,
                concealed(),
                &correlation,
            )
            .await;
        }
    };
    if !single_content_type(&headers, "application/json") {
        return audited_read_refusal(
            &service,
            &route,
            &surface,
            None,
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    let Ok(body) = bounded_body_to(body, MAX_LOOKUP_BODY_BYTES).await else {
        return audited_read_refusal(
            &service,
            &route,
            &surface,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let body = match parse_lookup_body(&body) {
        Ok(body) => body,
        Err(()) => {
            return audited_read_refusal(
                &service,
                &route,
                &surface,
                None,
                invalid_request(),
                &correlation,
            )
            .await;
        }
    };
    let selector = match resolve_lookup_selector(&service, &route, &surface, &claims, &body) {
        Ok(selector) => selector,
        Err(LookupResolutionError::InvalidRequest) => {
            return audited_read_refusal(
                &service,
                &route,
                &surface,
                None,
                invalid_request(),
                &correlation,
            )
            .await;
        }
        Err(LookupResolutionError::Unresolved) => {
            return audited_read_refusal(
                &service,
                &route,
                &surface,
                None,
                lookup_unresolved(),
                &correlation,
            )
            .await;
        }
    };
    if !readable_fields.is_subset(&surface.readable_fields) {
        return audited_read_refusal(&service, &route, &surface, None, concealed(), &correlation)
            .await;
    }
    let Some(operation) =
        lookup_query_operation_for_selector(&service, &route, &surface, &selector.selector_id)
    else {
        return audited_read_refusal(
            &service,
            &route,
            &surface,
            None,
            lookup_unresolved(),
            &correlation,
        )
        .await;
    };
    if !readable_fields
        .iter()
        .all(|field| operation.projection_fields.contains(field))
    {
        return audited_read_refusal(&service, &route, &surface, None, concealed(), &correlation)
            .await;
    }
    let request = RecordReadRequest {
        entity_id: route.entity_id.clone(),
        operation_id: route.id.clone(),
        method: route.method,
        context: surface.context,
        selected_fields: readable_fields,
        representation: negotiated_json_representation(&headers),
        adapter: CursorAdapter::Native,
        adapter_origin: None,
        geojson_next_link_prefix: None,
        kind: RecordReadKind::Lookup { selector },
        maximum_records: 2,
        request_history_after_proposal_version: None,
        correlation: correlation.clone(),
    };
    match service.records.lookup(request).await {
        Ok(Some(record)) => exact_read_no_store(record, surface.response_entity),
        Ok(None) => lookup_unresolved(),
        Err(ReadServiceError::Unavailable) => unavailable(),
        Err(ReadServiceError::CursorInvalid) => cursor_invalid(),
    }
}

async fn revision_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let Some(revisions) = &service.revisions else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let options = match QueryOptions::parse(raw_query.as_deref(), false) {
        Ok(options) => options,
        Err(QueryParseError::Invalid) => {
            return audited_known_revision_refusal(
                revisions.as_ref(),
                &route,
                &claims,
                path.get("record_id"),
                invalid_query(),
                &correlation,
            )
            .await;
        }
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_revision_concealment(
            revisions.as_ref(),
            &route,
            &options,
            &claims,
            path.get("record_id"),
            &correlation,
        )
        .await;
    };
    let Some(record_id) = path.get("record_id") else {
        return audited_revision_refusal(
            revisions.as_ref(),
            &route,
            &surface,
            None,
            concealed(),
            &correlation,
        )
        .await;
    };
    let revision = match route.revision_kind {
        Some(CompiledRevisionKind::List) if !path.contains_key("revision") => None,
        Some(CompiledRevisionKind::Detail) => {
            let Some(value) = path
                .get("revision")
                .and_then(|value| canonical_revision(value))
            else {
                return audited_revision_refusal(
                    revisions.as_ref(),
                    &route,
                    &surface,
                    Some(record_id),
                    concealed(),
                    &correlation,
                )
                .await;
            };
            Some(value)
        }
        _ => {
            return audited_revision_refusal(
                revisions.as_ref(),
                &route,
                &surface,
                Some(record_id),
                concealed(),
                &correlation,
            )
            .await;
        }
    };
    if !valid_canonical_record_uuid(record_id) {
        return audited_revision_refusal(
            revisions.as_ref(),
            &route,
            &surface,
            Some(record_id),
            concealed(),
            &correlation,
        )
        .await;
    }
    let Some(maximum_records) = route.maximum_records.map(usize::from) else {
        return unavailable();
    };
    if maximum_records == 0
        || maximum_records > usize::from(MAX_REVISION_HISTORY_RECORDS)
        || revision.is_some() && maximum_records != 1
        || revision.is_none() && maximum_records != usize::from(MAX_REVISION_HISTORY_RECORDS)
    {
        return unavailable();
    }
    let request = RevisionReadRequest {
        entity_id: route.entity_id.clone(),
        operation_id: route.id.clone(),
        method: route.method,
        record_id: record_id.clone(),
        revision,
        context: surface.context,
        selected_fields: surface.readable_fields,
        representation: negotiated_json_representation(&headers),
        maximum_records,
        correlation: correlation.clone(),
    };
    match route.revision_kind {
        Some(CompiledRevisionKind::List) => match revisions.list(request).await {
            Ok(Some(response)) => exact_read_no_store(response, surface.response_entity),
            Ok(None) => concealed(),
            Err(_) => unavailable(),
        },
        Some(CompiledRevisionKind::Detail) => match revisions.detail(request).await {
            Ok(Some(response)) => exact_read_no_store(response, surface.response_entity),
            Ok(None) => concealed(),
            Err(_) => unavailable(),
        },
        None => concealed(),
    }
}

async fn snapshot_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(snapshots) = &service.snapshots else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let options = match QueryOptions::parse_snapshot(raw_query.as_deref()) {
        Ok(options) => options,
        Err(_) => {
            return audited_known_read_refusal(
                &service,
                &route,
                &claims,
                None,
                concealed(),
                &correlation,
            )
            .await;
        }
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_read_concealment(&service, &route, &options, &claims, None, &correlation)
            .await;
    };
    let query = match read_query(
        &service,
        &route,
        &surface,
        &options,
        None,
        negotiated_json_representation(&headers),
        CursorAdapter::Native,
    )
    .await
    {
        Ok(Some(query)) if surface.read_path.is_none() => query,
        Ok(_) => return unavailable(),
        Err(error) => {
            let response = match error {
                ReadQueryError::Invalid => invalid_query(),
                ReadQueryError::CursorInvalid => cursor_invalid(),
            };
            return audited_read_refusal(&service, &route, &surface, None, response, &correlation)
                .await;
        }
    };
    let request = SnapshotReadRequest {
        entity_id: route.entity_id.clone(),
        operation_id: route.id.clone(),
        method: route.method,
        context: surface.context,
        selected_fields: query
            .cursor_binding
            .selected_fields
            .iter()
            .cloned()
            .collect(),
        maximum_records: usize::from(query.page_size) + 1,
        plan: query,
        correlation,
    };
    match snapshots.list(request).await {
        Ok(response) => exact_read_no_store(response, surface.response_entity),
        Err(ReadServiceError::Unavailable) => unavailable(),
        Err(ReadServiceError::CursorInvalid) => cursor_invalid(),
    }
}

async fn audited_known_revision_refusal(
    revisions: &dyn RevisionReadService,
    route: &CompiledRoute,
    claims: &VerifiedRequestClaims,
    target_record: Option<&String>,
    response: Response,
    correlation: &RequestCorrelation,
) -> Response {
    if claims.principal().is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::RevisionRequestInvalid);
    }
    match revisions
        .refusal(RevisionReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: claims.principal().map(str::to_owned),
            selected_access_profile: None,
            purpose_present: claims.purpose().is_some(),
            correlation: correlation.clone(),
        })
        .await
    {
        Ok(()) => response,
        Err(_) => unavailable(),
    }
}

async fn audited_revision_refusal(
    revisions: &dyn RevisionReadService,
    route: &CompiledRoute,
    surface: &AuthorizedSurface<'_>,
    target_record: Option<&String>,
    response: Response,
    correlation: &RequestCorrelation,
) -> Response {
    if surface.context.principal().is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::RevisionRefused);
    }
    match revisions
        .refusal(RevisionReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: surface.context.principal().map(str::to_owned),
            selected_access_profile: Some(surface.context.selected_profile().to_owned()),
            purpose_present: surface.context.purpose().is_some(),
            correlation: correlation.clone(),
        })
        .await
    {
        Ok(()) => response,
        Err(_) => unavailable(),
    }
}

async fn audited_revision_concealment(
    revisions: &dyn RevisionReadService,
    route: &CompiledRoute,
    options: &QueryOptions,
    claims: &VerifiedRequestClaims,
    target_record: Option<&String>,
    correlation: &RequestCorrelation,
) -> Response {
    if claims.principal().is_none() {
        return anonymous_refusal(concealed(), AnonymousRefusalReason::RevisionConcealed);
    }
    let selected_access_profile = options.access_profile().and_then(|profile| {
        route
            .access_profiles
            .iter()
            .any(|candidate| candidate == profile)
            .then_some(profile.clone())
    });
    match revisions
        .refusal(RevisionReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: claims.principal().map(str::to_owned),
            selected_access_profile,
            purpose_present: claims.purpose().is_some(),
            correlation: correlation.clone(),
        })
        .await
    {
        Ok(()) => concealed(),
        Err(_) => unavailable(),
    }
}

async fn audited_known_read_refusal(
    service: &HttpService,
    route: &CompiledRoute,
    claims: &VerifiedRequestClaims,
    target_record: Option<&String>,
    response: Response,
    correlation: &RequestCorrelation,
) -> Response {
    if claims.principal().is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::ReadRequestInvalid);
    }
    match service
        .read_refusal(
            route.operation,
            RecordReadRefusal {
                method: route.method,
                operation_id: route.id.clone(),
                target_record: target_record.cloned(),
                principal: claims.principal().map(str::to_owned),
                selected_access_profile: None,
                purpose_present: claims.purpose().is_some(),
                correlation: correlation.clone(),
            },
        )
        .await
    {
        Ok(()) => response,
        Err(_) => unavailable(),
    }
}

async fn audited_read_refusal(
    service: &HttpService,
    route: &CompiledRoute,
    surface: &AuthorizedSurface<'_>,
    target_record: Option<&String>,
    response: Response,
    correlation: &RequestCorrelation,
) -> Response {
    if surface.context.principal().is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::ReadRefused);
    }
    match service
        .read_refusal(
            route.operation,
            RecordReadRefusal {
                method: route.method,
                operation_id: route.id.clone(),
                target_record: target_record.cloned(),
                principal: surface.context.principal().map(str::to_owned),
                selected_access_profile: Some(surface.context.selected_profile().to_owned()),
                purpose_present: surface.context.purpose().is_some(),
                correlation: correlation.clone(),
            },
        )
        .await
    {
        Ok(()) => response,
        Err(_) => unavailable(),
    }
}

async fn audited_read_concealment(
    service: &HttpService,
    route: &CompiledRoute,
    options: &QueryOptions,
    claims: &VerifiedRequestClaims,
    target_record: Option<&String>,
    correlation: &RequestCorrelation,
) -> Response {
    if claims.principal().is_none() {
        return anonymous_refusal(concealed(), AnonymousRefusalReason::ReadConcealed);
    }
    let selected_access_profile = options.access_profile().and_then(|profile| {
        route
            .access_profiles
            .iter()
            .any(|candidate| candidate == profile)
            .then_some(profile.clone())
    });
    match service
        .read_refusal(
            route.operation,
            RecordReadRefusal {
                method: route.method,
                operation_id: route.id.clone(),
                target_record: target_record.cloned(),
                principal: claims.principal().map(str::to_owned),
                selected_access_profile,
                purpose_present: claims.purpose().is_some(),
                correlation: correlation.clone(),
            },
        )
        .await
    {
        Ok(()) => concealed(),
        Err(_) => unavailable(),
    }
}

async fn create_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key") else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    if !valid_idempotency_key(idempotency_key) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    }
    if !single_content_type(&headers, "application/json") {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    let Ok(body) = bounded_body(body).await else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Ok(data) = parse_create_body(&body) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    match mutations
        .create(CreateMutationInput {
            route_id: &route.id,
            idempotency_key,
            context: &surface.context,
            entity_id: &route.entity_id,
            data,
            response_fields: surface.readable_fields,
            representation: negotiated_record_representation(&headers),
            correlation: &correlation,
        })
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
async fn patch_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(record_id) = path.get("record_id") else {
        return invalid_request();
    };
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &QueryOptions::default(),
            &claims,
            Some(record_id.as_str()),
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &options,
            &claims,
            Some(record_id.as_str()),
            &correlation,
        )
        .await;
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key") else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    if !valid_idempotency_key(idempotency_key) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    }
    let Some(if_match) = single_header(&headers, IF_MATCH.as_str()) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            precondition_required(),
            &correlation,
        )
        .await;
    };
    if !valid_if_match(if_match) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            precondition_failed(),
            &correlation,
        )
        .await;
    }
    if !single_content_type(&headers, "application/json-patch+json") {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    let Ok(body) = bounded_body(body).await else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Ok(document) = parse_json_strict(&body) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Ok(patch) = parse_json_patch_document(document) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    match mutations
        .patch(
            ConditionalMutationInput {
                route_id: &route.id,
                idempotency_key,
                if_match,
                context: &surface.context,
                entity_id: &route.entity_id,
                record_id,
                response_fields: surface.readable_fields,
                representation: negotiated_record_representation(&headers),
                correlation: &correlation,
            },
            patch,
        )
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

async fn batch_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &QueryOptions::default(),
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    };
    let Some(batch) = surface.entity.batch.as_ref() else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key") else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    if !valid_idempotency_key(idempotency_key) || headers.contains_key(IF_MATCH) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    }
    if !single_content_type(&headers, "application/json") {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    let Ok(body) = bounded_body_to(body, batch.maximum_bytes as usize).await else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Ok(parsed) = parse_batch_body(&body, usize::from(batch.maximum_items)) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
            &correlation,
        )
        .await;
    };
    match mutations
        .batch(BatchMutationInput {
            route_id: &route.id,
            idempotency_key,
            context: &surface.context,
            entity_id: &route.entity_id,
            items: parsed.items,
            change_context: parsed.change_context,
            response_fields: surface.readable_fields,
            body_bytes: body.len(),
            correlation: &correlation,
        })
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
async fn tombstone_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(record_id) = path.get("record_id") else {
        return invalid_request();
    };
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &QueryOptions::default(),
            &claims,
            Some(record_id.as_str()),
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &options,
            &claims,
            Some(record_id.as_str()),
            &correlation,
        )
        .await;
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key") else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    if !valid_idempotency_key(idempotency_key) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    }
    let Some(if_match) = single_header(&headers, IF_MATCH.as_str()) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            precondition_required(),
            &correlation,
        )
        .await;
    };
    if !valid_if_match(if_match) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            precondition_failed(),
            &correlation,
        )
        .await;
    }
    if headers.contains_key(CONTENT_TYPE) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    if !body_is_empty(body).await {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    }
    match mutations
        .tombstone(ConditionalMutationInput {
            route_id: &route.id,
            idempotency_key,
            if_match,
            context: &surface.context,
            entity_id: &route.entity_id,
            record_id,
            response_fields: surface.readable_fields,
            representation: negotiated_record_representation(&headers),
            correlation: &correlation,
        })
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
async fn request_action_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(path): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(record_id) = path.get("record_id") else {
        return invalid_request();
    };
    let Ok(options) = QueryOptions::parse(raw_query.as_deref(), false) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &QueryOptions::default(),
            &claims,
            Some(record_id.as_str()),
            &correlation,
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &options,
            &claims,
            Some(record_id.as_str()),
            &correlation,
        )
        .await;
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key") else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    if !valid_idempotency_key(idempotency_key) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    }
    let Some(if_match) = single_header(&headers, IF_MATCH.as_str()) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            precondition_required(),
            &correlation,
        )
        .await;
    };
    if !valid_if_match(if_match) {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            precondition_failed(),
            &correlation,
        )
        .await;
    }
    if !single_content_type(&headers, "application/json") {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            unsupported_media_type(),
            &correlation,
        )
        .await;
    }
    let Ok(body) = bounded_body(body).await else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Ok(action) =
        parse_request_action_body(route.operation, route.request_stage.as_deref(), &body)
    else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            Some(record_id.as_str()),
            invalid_request(),
            &correlation,
        )
        .await;
    };
    let Some(target_authority) =
        request_action_target_authority(surface.entity, &route, &surface.context, &claims)
    else {
        return audited_mutation_concealment(
            mutations,
            &route,
            &options,
            &claims,
            Some(record_id.as_str()),
            &correlation,
        )
        .await;
    };
    let automatic_apply_authority = surface.entity.change_request.as_ref().and_then(|plan| {
        request_automatic_apply_authority(plan, surface.context.selected_profile(), &claims)
    });
    match mutations
        .request_action(RequestActionInput {
            route_id: &route.id,
            idempotency_key,
            if_match,
            context: &surface.context,
            entity_id: &route.entity_id,
            record_id,
            action,
            response_fields: surface.readable_fields,
            target_authority,
            automatic_apply_authority,
            correlation: &correlation,
        })
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

fn request_action_target_authority(
    entity: &CompiledEntity,
    route: &CompiledRoute,
    context: &AuthorizedRequestContext,
    claims: &VerifiedRequestClaims,
) -> Option<Vec<RequestActionTargetAuthority>> {
    if !is_request_operation(route.operation) {
        return Some(Vec::new());
    }
    let plan = entity.change_request.as_ref()?;
    if !plan.actions.iter().any(|action| {
        action.operation.access_operation() == route.operation
            && action.review_stage.as_deref() == route.request_stage.as_deref()
    }) {
        return None;
    }
    match route.operation {
        Operation::ApproveRequest | Operation::RejectRequest | Operation::RequestRevision => {
            let stage = route.request_stage.as_deref()?;
            plan.target_entities
                .iter()
                .map(|target_entity_id| {
                    let grant = plan.review_grants.iter().find(|grant| {
                        grant.profile_id == context.selected_profile()
                            && grant.stage == stage
                            && grant.target_entity_id == *target_entity_id
                    })?;
                    Some(RequestActionTargetAuthority {
                        target_entity_id: target_entity_id.clone(),
                        readable_fields: grant.readable_fields.clone(),
                        row_boundaries: verified_row_boundaries_from_sources(
                            &grant.row_boundaries,
                            claims,
                        )?,
                    })
                })
                .collect()
        }
        Operation::ApplyRequest => plan
            .target_entities
            .iter()
            .map(|target_entity_id| {
                let grant = plan.apply_grants.iter().find(|grant| {
                    grant.profile_id == context.selected_profile()
                        && grant.target_entity_id == *target_entity_id
                })?;
                Some(RequestActionTargetAuthority {
                    target_entity_id: target_entity_id.clone(),
                    readable_fields: BTreeSet::new(),
                    row_boundaries: verified_row_boundaries_from_sources(
                        &grant.row_boundaries,
                        claims,
                    )?,
                })
            })
            .collect(),
        Operation::SubmitRequest | Operation::ReviseRequest | Operation::CancelRequest => {
            Some(Vec::new())
        }
        _ => None,
    }
}

fn request_automatic_apply_authority(
    plan: &crate::model::CompiledChangeRequest,
    selected_profile: &str,
    claims: &VerifiedRequestClaims,
) -> Option<Vec<RequestActionTargetAuthority>> {
    plan.target_entities
        .iter()
        .map(|target_entity_id| {
            let grant = plan.apply_grants.iter().find(|grant| {
                grant.profile_id == selected_profile && grant.target_entity_id == *target_entity_id
            })?;
            Some(RequestActionTargetAuthority {
                target_entity_id: target_entity_id.clone(),
                readable_fields: BTreeSet::new(),
                row_boundaries: verified_row_boundaries_from_sources(
                    &grant.row_boundaries,
                    claims,
                )?,
            })
        })
        .collect()
}

fn request_action_requires_automatic_apply_if_ready(
    plan: &CompiledChangeRequest,
    route: &CompiledRoute,
) -> bool {
    let may_apply = match plan.application.mode {
        CompiledChangeRequestApplicationMode::Automatic => true,
        CompiledChangeRequestApplicationMode::Planner => plan
            .application
            .allowed_dispositions
            .contains(&CompiledChangeRequestDisposition::Apply),
        CompiledChangeRequestApplicationMode::Manual => false,
    };
    if !may_apply {
        return false;
    }
    match route.operation {
        Operation::SubmitRequest => plan.review_mode == CompiledChangeRequestReviewMode::None,
        Operation::ApproveRequest => {
            plan.review_mode == CompiledChangeRequestReviewMode::Stages
                && route.request_stage.as_deref()
                    == plan.stages.last().map(|stage| stage.id.as_str())
        }
        _ => false,
    }
}

fn request_visibility_authority(
    service: &HttpService,
    entity: &CompiledEntity,
    selected_profile: &str,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> (Vec<VerifiedRequestAction>, Vec<VerifiedRequestPresence>) {
    let actions = if entity.change_request.is_some() {
        service
            .registry
            .routes()
            .routes
            .iter()
            .filter(|route| route.entity_id == entity.id && is_request_operation(route.operation))
            .filter_map(|route| {
                let surface = authorize_direct_route_base(service, route, claims, options, false)?;
                if surface.context.selected_profile() != selected_profile {
                    return None;
                }
                let target_authority =
                    request_action_target_authority(entity, route, &surface.context, claims)?;
                let target_authority = target_authority
                    .into_iter()
                    .map(|authority| {
                        VerifiedRequestTargetAuthority::new(
                            authority.target_entity_id,
                            authority.readable_fields,
                            authority.row_boundaries,
                        )
                    })
                    .collect();
                let automatic_apply_authority = entity.change_request.as_ref().and_then(|plan| {
                    request_automatic_apply_authority(plan, selected_profile, claims).map(
                        |authority| {
                            authority
                                .into_iter()
                                .map(|authority| {
                                    VerifiedRequestTargetAuthority::new(
                                        authority.target_entity_id,
                                        authority.readable_fields,
                                        authority.row_boundaries,
                                    )
                                })
                                .collect()
                        },
                    )
                });
                Some(VerifiedRequestAction::new(
                    route.id.clone(),
                    route.method,
                    route.path.clone(),
                    route.operation,
                    route.request_stage.clone(),
                    surface.readable_fields,
                    VerifiedRequestActionAuthority::new(
                        target_authority,
                        automatic_apply_authority,
                        request_action_requires_automatic_apply_if_ready(
                            entity
                                .change_request
                                .as_ref()
                                .expect("change request checked"),
                            route,
                        ),
                    ),
                ))
            })
            .collect()
    } else {
        Vec::new()
    };
    let presence = entity
        .access_profiles
        .get(selected_profile)
        .into_iter()
        .flat_map(|profile| &profile.request_presence)
        .filter_map(|grant| {
            let plan = service
                .registry
                .entities()
                .get(&grant.request_type)?
                .change_request
                .as_ref()?;
            if !plan.presence_grants.iter().any(|compiled| {
                compiled.profile_id == selected_profile
                    && compiled.target_entity_id == entity.id
                    && compiled.request_row_boundaries == grant.row_boundaries
            }) {
                return None;
            }
            let row_boundaries =
                verified_row_boundaries_from_sources(&grant.row_boundaries, claims)?;
            Some(VerifiedRequestPresence::new(
                grant.request_type.clone(),
                row_boundaries,
            ))
        })
        .collect();
    (actions, presence)
}

async fn audited_mutation_refusal(
    mutations: &crate::postgres::PostgresRecordMutationService,
    route: &CompiledRoute,
    context: &AuthorizedRequestContext,
    target_record: Option<&str>,
    response: Response,
    correlation: &RequestCorrelation,
) -> Response {
    if context.principal().is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::MutationRefused);
    }
    match mutations
        .record_refusal(crate::audit::HttpRefusalAudit {
            method: route.method,
            operation_id: &route.id,
            target_record,
            action_id: None,
            principal: context.principal(),
            selected_access_profile: Some(context.selected_profile()),
            purpose_present: context.purpose().is_some(),
            correlation,
        })
        .await
    {
        Ok(()) => response,
        Err(_) => mutation_problem(MutationError::Unavailable),
    }
}

async fn audited_mutation_concealment(
    mutations: &crate::postgres::PostgresRecordMutationService,
    route: &CompiledRoute,
    options: &QueryOptions,
    claims: &VerifiedRequestClaims,
    target_record: Option<&str>,
    correlation: &RequestCorrelation,
) -> Response {
    if claims.principal().is_none() {
        return anonymous_refusal(concealed(), AnonymousRefusalReason::MutationConcealed);
    }
    // Only a profile the compiled route grants may reach the journal, so an
    // unknown caller-supplied value is recorded as absent.
    let selected_profile = match options.access_profile() {
        Some(profile) => route
            .access_profiles
            .iter()
            .any(|candidate| candidate == profile)
            .then_some(profile.as_str()),
        None => Some(route.default_access_profile.as_str()),
    };
    match mutations
        .record_refusal(crate::audit::HttpRefusalAudit {
            method: route.method,
            operation_id: &route.id,
            target_record,
            action_id: None,
            principal: claims.principal(),
            selected_access_profile: selected_profile,
            purpose_present: claims.purpose().is_some(),
            correlation,
        })
        .await
    {
        Ok(()) => concealed(),
        Err(_) => mutation_problem(MutationError::Unavailable),
    }
}

async fn not_found() -> Response {
    concealed()
}

struct AuthorizedSurface<'a> {
    route: &'a CompiledRoute,
    entity: &'a CompiledEntity,
    response_entity: &'a CompiledEntity,
    context: AuthorizedRequestContext,
    readable_fields: BTreeSet<String>,
    read_path: Option<&'a CompiledReadPath>,
}

fn visible_surfaces<'a>(
    service: &'a HttpService,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Vec<AuthorizedSurface<'a>> {
    service
        .registry
        .routes()
        .routes
        .iter()
        .filter(|route| served_operation(service, route))
        .filter_map(|route| authorize_route(service, route, claims, options))
        .collect()
}

fn visible_metadata_entries<'a>(
    service: &'a HttpService,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Vec<(&'a CompiledMetadataEntity, &'a CompiledMetadataEntry)> {
    visible_surfaces(service, claims, options)
        .into_iter()
        .filter_map(|surface| metadata_entry_for_surface(service, &surface))
        .collect()
}

fn metadata_entry_for_surface<'a>(
    service: &'a HttpService,
    surface: &AuthorizedSurface<'_>,
) -> Option<(&'a CompiledMetadataEntity, &'a CompiledMetadataEntry)> {
    let entity = service
        .registry
        .metadata()
        .entities
        .iter()
        .find(|entity| entity.id == surface.route.entity_id)?;
    let entry = entity.entries.iter().find(|entry| {
        entry.route_id == surface.route.id
            && entry.operation == surface.route.operation
            && entry.access_profile == surface.context.selected_profile()
            && entry.response_entity_id == surface.response_entity.id
            && entry.readable_fields == surface.readable_fields
    })?;
    Some((entity, entry))
}

fn permitted_request_types(surfaces: &[AuthorizedSurface<'_>]) -> BTreeSet<String> {
    surfaces
        .iter()
        .flat_map(|surface| {
            std::iter::once(surface.response_entity.id.clone()).chain(
                surface
                    .context
                    .request_presence()
                    .iter()
                    .map(|grant| grant.request_entity_id().to_owned()),
            )
        })
        .collect()
}

fn metadata_change_control(
    service: &HttpService,
    entity: &CompiledEntity,
    permitted_requests: &BTreeSet<String>,
) -> Value {
    let controlled_operations = entity
        .change_control
        .as_ref()
        .map(|control| {
            control
                .required_for
                .iter()
                .map(|operation| operation_name(*operation))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let eligible_request_types = service
        .registry
        .entities()
        .values()
        .filter(|request_entity| permitted_requests.contains(&request_entity.id))
        .filter_map(|request_entity| {
            request_entity
                .change_request
                .as_ref()
                .filter(|plan| plan.target_entities.contains(&entity.id))
                .map(|_| {
                    json!({
                        "id": request_entity.id,
                        "primaryDataset": request_entity.primary_dataset,
                        "route": request_entity.route,
                    })
                })
        })
        .collect::<Vec<_>>();
    json!({
        "controlledOperations": controlled_operations,
        "eligibleRequestTypes": eligible_request_types,
    })
}

fn authorize_route<'a>(
    service: &'a HttpService,
    route: &'a CompiledRoute,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Option<AuthorizedSurface<'a>> {
    if let Some((read_path, response_entity)) = read_path_for_route(service, route) {
        return authorize_read_path_route(
            service,
            route,
            read_path,
            response_entity,
            claims,
            options,
        );
    }
    authorize_direct_route(service, route, claims, options)
}

fn authorize_direct_route<'a>(
    service: &'a HttpService,
    route: &'a CompiledRoute,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Option<AuthorizedSurface<'a>> {
    authorize_direct_route_base(service, route, claims, options, true)
}

fn authorize_direct_route_base<'a>(
    service: &'a HttpService,
    route: &'a CompiledRoute,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
    include_request_visibility: bool,
) -> Option<AuthorizedSurface<'a>> {
    let access = access_entry_for_route(service, route)?;
    let selected_profile = options
        .access_profile()
        .map(String::as_str)
        .unwrap_or(&access.default_profile_id);
    if !access.profile_ids.contains(selected_profile)
        || !route
            .access_profiles
            .iter()
            .any(|id| id == selected_profile)
    {
        return None;
    }
    let entity = service.registry.entities().get(&route.entity_id)?;
    let profile = entity.access_profiles.get(selected_profile)?;
    if !profile.operations.contains(&route.operation) {
        return None;
    }
    if route.operation == Operation::Revisions && (profile.anonymous || !profile.revision_access) {
        return None;
    }
    if route.operation == Operation::Snapshot && profile.anonymous {
        return None;
    }
    if matches!(
        route.operation,
        Operation::Create | Operation::Patch | Operation::Tombstone | Operation::Batch
    ) && profile.anonymous
    {
        return None;
    }
    if profile.anonymous && entity.classification != Classification::Public {
        return None;
    }
    let row_boundaries = authorize_profile_claims(profile, claims).ok()?;
    let readable_fields = profile
        .readable_fields
        .iter()
        .filter(|field| {
            route.operation != Operation::Snapshot
                || entity
                    .stored_fields
                    .iter()
                    .any(|stored| stored.logical.id == **field)
        })
        .filter(|field| {
            !profile.anonymous
                || entity
                    .fields
                    .get(*field)
                    .is_some_and(|field| field.classification == Classification::Public)
        })
        .cloned()
        .collect();
    let mut context = AuthorizedRequestContext::new(
        claims.principal().map(str::to_owned),
        claims.purpose().map(str::to_owned),
        selected_profile.to_owned(),
        row_boundaries,
    );
    if include_request_visibility {
        let (actions, presence) =
            request_visibility_authority(service, entity, selected_profile, claims, options);
        context = context.with_request_visibility(actions, presence);
    }
    Some(AuthorizedSurface {
        route,
        entity,
        response_entity: entity,
        context,
        readable_fields,
        read_path: None,
    })
}

fn authorize_read_path_route<'a>(
    service: &'a HttpService,
    route: &'a CompiledRoute,
    read_path: &'a CompiledReadPath,
    response_entity: &'a CompiledEntity,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Option<AuthorizedSurface<'a>> {
    let access = access_entry_for_route(service, route)?;
    let selected_profile = options
        .access_profile()
        .map(String::as_str)
        .unwrap_or(&access.default_profile_id);
    if !access.profile_ids.contains(selected_profile)
        || !route
            .access_profiles
            .iter()
            .any(|id| id == selected_profile)
    {
        return None;
    }
    let entity = service.registry.entities().get(&route.entity_id)?;
    let profile = entity.access_profiles.get(selected_profile)?;
    let grant = profile
        .read_paths
        .iter()
        .find(|grant| grant.path == read_path.id)?;
    if route.operation != Operation::List || route.query_kind != Some(CompiledQueryKind::List) {
        return None;
    }
    if profile.anonymous
        && (entity.classification != Classification::Public
            || response_entity.classification != Classification::Public)
    {
        return None;
    }
    let row_boundaries = authorize_profile_claims(profile, claims).ok()?;
    let readable_fields = grant
        .readable_fields
        .iter()
        .filter(|field| {
            !profile.anonymous
                || response_entity
                    .fields
                    .get(*field)
                    .is_some_and(|field| field.classification == Classification::Public)
        })
        .cloned()
        .collect();
    Some(AuthorizedSurface {
        route,
        entity,
        response_entity,
        context: AuthorizedRequestContext::new(
            claims.principal().map(str::to_owned),
            claims.purpose().map(str::to_owned),
            selected_profile.to_owned(),
            row_boundaries,
        ),
        readable_fields,
        read_path: Some(read_path),
    })
}

fn access_entry_for_route<'a>(
    service: &'a HttpService,
    route: &CompiledRoute,
) -> Option<&'a crate::model::CompiledAccessEntry> {
    service
        .registry
        .access()
        .entries
        .iter()
        .find(|entry| entry.route_id == route.id && entry.operation == route.operation)
        .or_else(|| {
            if route.id.contains(".path.") || is_request_operation(route.operation) {
                return None;
            }
            service.registry.access().entries.iter().find(|entry| {
                entry.entity_id == route.entity_id && entry.operation == route.operation
            })
        })
}

fn read_path_for_route<'a>(
    service: &'a HttpService,
    route: &CompiledRoute,
) -> Option<(&'a CompiledReadPath, &'a CompiledEntity)> {
    let entity = service.registry.entities().get(&route.entity_id)?;
    let path = entity.read_paths.values().find(|path| {
        route.id == format!("records.{}.path.{}", entity.id, path.id)
            && route.path == format!("/v1/records/{}/{{record_id}}/{}", entity.route, path.route)
    })?;
    let response_entity = service.registry.entities().get(&path.to)?;
    Some((path, response_entity))
}

fn is_request_operation(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::SubmitRequest
            | Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ReviseRequest
            | Operation::CancelRequest
            | Operation::ApplyRequest
    )
}

fn served_operation(service: &HttpService, route: &CompiledRoute) -> bool {
    match route.operation {
        Operation::Invoke => false,
        Operation::Get | Operation::List => true,
        Operation::Lookup => true,
        Operation::Create => service.mutations.is_some(),
        Operation::Batch => {
            service.mutations.is_some()
                && service
                    .registry
                    .entities()
                    .get(&route.entity_id)
                    .is_some_and(|entity| entity.batch.is_some())
        }
        Operation::Patch => {
            service.mutations.is_some()
                && service
                    .registry
                    .entities()
                    .get(&route.entity_id)
                    .is_some_and(|entity| {
                        entity.mutation_mode == crate::contract::MutationMode::Mutable
                    })
        }
        Operation::Tombstone => {
            service.mutations.is_some()
                && service
                    .registry
                    .entities()
                    .get(&route.entity_id)
                    .is_some_and(|entity| {
                        entity.mutation_mode == crate::contract::MutationMode::Mutable
                            && entity.tombstone
                    })
        }
        Operation::Revisions => service.revisions.is_some(),
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => {
            service.mutations.is_some()
                && service
                    .registry
                    .entities()
                    .get(&route.entity_id)
                    .and_then(|entity| entity.change_request.as_ref())
                    .is_some_and(|plan| {
                        plan.actions.iter().any(|action| {
                            action.operation.access_operation() == route.operation
                                && action.review_stage.as_deref() == route.request_stage.as_deref()
                        })
                    })
        }
        Operation::Snapshot => service.snapshots.is_some(),
    }
}

/// Shared by real HTTP admission and offline synthetic access previews.
/// Detailed reasons never cross the public HTTP concealment boundary.
pub(crate) fn authorize_profile_claims(
    profile: &AccessProfileSource,
    claims: &VerifiedRequestClaims,
) -> Result<Vec<VerifiedRowBoundary>, &'static str> {
    if !profile.anonymous
        && (profile.principal_claim.as_deref() != claims.principal_claim()
            || claims.principal().is_none())
    {
        return Err("principal_missing_or_mismatched");
    }
    if !profile
        .required_scopes
        .iter()
        .all(|scope| claims.has_scope(scope))
    {
        return Err("required_scope_missing");
    }
    if !profile.required_purposes.is_empty()
        && !claims
            .purpose()
            .is_some_and(|purpose| profile.required_purposes.contains(purpose))
    {
        return Err("purpose_missing_or_not_allowed");
    }
    verified_row_boundaries(profile, claims).ok_or("row_claim_missing_or_wrong_cardinality")
}

fn verified_row_boundaries(
    profile: &AccessProfileSource,
    claims: &VerifiedRequestClaims,
) -> Option<Vec<VerifiedRowBoundary>> {
    verified_row_boundaries_from_sources(&profile.row_boundaries, claims)
}

fn verified_row_boundaries_from_sources(
    row_boundaries: &[RowBoundarySource],
    claims: &VerifiedRequestClaims,
) -> Option<Vec<VerifiedRowBoundary>> {
    row_boundaries
        .iter()
        .map(|boundary| {
            let values = claims.direct_claim(&boundary.claim)?.values();
            let operator = match boundary.operator {
                BoundaryOperator::Equals if values.len() == 1 => RowBoundaryOperator::Equals,
                BoundaryOperator::Equals => return None,
                BoundaryOperator::In => RowBoundaryOperator::In,
            };
            Some(VerifiedRowBoundary::new(
                boundary.field.clone(),
                operator,
                values,
            ))
        })
        .collect()
}

async fn read_query(
    service: &HttpService,
    route: &CompiledRoute,
    surface: &AuthorizedSurface<'_>,
    options: &QueryOptions,
    root_id: Option<&str>,
    representation: CursorRepresentation,
    adapter: CursorAdapter,
) -> Result<Option<CompiledReadQuery>, ReadQueryError> {
    let Some(kind) = route.query_kind else {
        return Ok(None);
    };
    let Some(operation) = query_operation_for_route(service, route, surface, kind) else {
        return Err(ReadQueryError::Invalid);
    };
    if (kind == CompiledQueryKind::Snapshot) != options.historical.is_some() {
        return Err(ReadQueryError::Invalid);
    }
    let scope = if let Some(historical) = &options.historical {
        if surface.read_path.is_some() || root_id.is_some() {
            return Err(ReadQueryError::Invalid);
        }
        if let Some(reference) = &historical.snapshot {
            crate::history_reference::SnapshotReference::parse(reference)
                .map_err(|_| ReadQueryError::Invalid)?;
        }
        CursorQueryScope::Snapshot {
            reference: historical.snapshot.clone(),
        }
    } else {
        cursor_scope(surface, root_id)?
    };
    let adapter_origin =
        cursor_adapter_origin(service, adapter).map_err(|_| ReadQueryError::Invalid)?;
    if let Some(token) = options.skiptoken() {
        let payload = service
            .cursors
            .open_after_authorization(token, now_unix_seconds(), |payload| {
                let bound_scope = if kind == CompiledQueryKind::Snapshot {
                    match &payload.query.scope {
                        CursorQueryScope::Snapshot {
                            reference: Some(reference),
                        } => {
                            crate::history_reference::SnapshotReference::parse(reference)
                                .map_err(|_| CursorError::Mismatch)?;
                            &payload.query.scope
                        }
                        _ => return Err(CursorError::Mismatch),
                    }
                } else {
                    &scope
                };
                if payload.binding.route_id != route.id
                    || payload.binding.query_operation_id != operation.id
                    || payload.binding.query_kind != kind
                    || payload.binding.selected_profile != surface.context.selected_profile()
                    || payload.binding.include_count != payload.query.include_count
                    || payload.binding.page_size != payload.query.page_size
                    || payload.binding.temporal_instant != payload.query.temporal_instant
                    || &payload.query.scope != bound_scope
                    || payload.binding.representation != representation
                    || payload.binding.adapter != adapter
                {
                    return Err(CursorError::Mismatch);
                }
                let fields = payload
                    .binding
                    .selected_fields
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let projection = read_projection_from_cursor(
                    surface.response_entity,
                    operation,
                    &fields,
                    &payload.query.projection,
                )
                .map_err(|_| CursorError::Mismatch)?;
                let filter = payload
                    .query
                    .filter
                    .as_ref()
                    .map(|filter| {
                        read_filter_expr_from_cursor(surface.response_entity, operation, filter)
                    })
                    .transpose()
                    .map_err(|_| CursorError::Mismatch)?;
                let order = payload
                    .query
                    .order
                    .as_ref()
                    .map(|order| {
                        read_order_clause_from_cursor(surface.response_entity, operation, order)
                    })
                    .transpose()
                    .map_err(|_| CursorError::Mismatch)?;
                let spatial = payload
                    .query
                    .spatial
                    .as_ref()
                    .map(|spatial| read_spatial_from_cursor(operation, spatial))
                    .transpose()
                    .map_err(|_| CursorError::Mismatch)?;
                validate_query_shape(
                    surface.response_entity,
                    operation,
                    filter.as_ref(),
                    spatial.as_ref(),
                    order.as_ref(),
                    payload.binding.page_size,
                )
                .map_err(|_| CursorError::Mismatch)?;
                cursor_binding(
                    service,
                    route,
                    surface,
                    operation,
                    CursorBindingQuery {
                        selected_fields: &fields,
                        projection: &projection,
                        filter: filter.as_ref(),
                        spatial: spatial.as_ref(),
                        order: order.as_ref(),
                        include_count: payload.binding.include_count,
                        page_size: payload.binding.page_size,
                        temporal_instant: payload.binding.temporal_instant.as_deref(),
                        scope: bound_scope,
                        representation,
                        adapter,
                        adapter_origin: adapter_origin.as_deref(),
                    },
                )
            })
            .map_err(|_| ReadQueryError::CursorInvalid)?;
        let fields = payload
            .binding
            .selected_fields
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if fields.is_empty() || !fields.is_subset(&surface.readable_fields) {
            return Err(ReadQueryError::CursorInvalid);
        }
        let projection = read_projection_from_cursor(
            surface.response_entity,
            operation,
            &fields,
            &payload.query.projection,
        )?;
        let filter = payload
            .query
            .filter
            .as_ref()
            .map(|filter| read_filter_expr_from_cursor(surface.response_entity, operation, filter))
            .transpose()?;
        let order = payload
            .query
            .order
            .as_ref()
            .map(|order| read_order_clause_from_cursor(surface.response_entity, operation, order))
            .transpose()?;
        let spatial = payload
            .query
            .spatial
            .as_ref()
            .map(|spatial| read_spatial_from_cursor(operation, spatial))
            .transpose()?;
        return Ok(Some(CompiledReadQuery {
            route_id: route.id.clone(),
            query_operation_id: operation.id.clone(),
            kind,
            cursor_binding: payload.binding.clone(),
            cursor_query: payload.query.clone(),
            projection,
            filter,
            spatial,
            order,
            include_count: payload.binding.include_count,
            page_size: payload.binding.page_size,
            temporal_instant: payload.binding.temporal_instant,
            adapter: payload.binding.adapter,
            adapter_origin,
            continuation: Some(payload.continuation),
        }));
    }

    let query_options = options.query_options().ok_or(ReadQueryError::Invalid)?;
    let fields = match resolve_select(
        surface.response_entity,
        &surface.readable_fields,
        query_options.select.as_ref(),
    ) {
        Ok(Some(fields)) => fields,
        Ok(None) => operation.projection_fields.iter().cloned().collect(),
        Err(()) => return Err(ReadQueryError::Invalid),
    };
    if fields.is_empty()
        || !fields.is_subset(&surface.readable_fields)
        || !fields
            .iter()
            .all(|field| operation.projection_fields.contains(field))
    {
        return Err(ReadQueryError::Invalid);
    }
    let projection = projection_plan(surface.response_entity, &fields)?;
    let filter = first_page_filter_expr(
        surface.response_entity,
        operation,
        query_options.filter.as_ref(),
    )?;
    let spatial = first_page_spatial_query(surface, operation, query_options.bbox.as_ref())?;
    let order = match &query_options.orderby {
        Some(orderby) => {
            if orderby.direction != strict_query::OrderDirection::Asc {
                return Err(ReadQueryError::Invalid);
            }
            Some(resolve_order_clause(
                surface.response_entity,
                operation,
                orderby,
            )?)
        }
        None => None,
    };
    let page_size = query_options
        .top
        .map(u16::try_from)
        .transpose()
        .map_err(|_| ReadQueryError::Invalid)?
        .unwrap_or(operation.max_page_size);
    let include_count = query_options.count.unwrap_or(false);
    if include_count && !operation.allow_count {
        return Err(ReadQueryError::Invalid);
    }
    validate_query_shape(
        surface.response_entity,
        operation,
        filter.as_ref(),
        spatial.as_ref(),
        order.as_ref(),
        page_size,
    )?;
    let temporal_instant = temporal_instant_for(kind, options, surface.response_entity)?;
    let binding = cursor_binding(
        service,
        route,
        surface,
        operation,
        CursorBindingQuery {
            selected_fields: &fields,
            projection: &projection,
            filter: filter.as_ref(),
            spatial: spatial.as_ref(),
            order: order.as_ref(),
            include_count,
            page_size,
            temporal_instant: temporal_instant.as_deref(),
            scope: &scope,
            representation,
            adapter,
            adapter_origin: adapter_origin.as_deref(),
        },
    )
    .map_err(|_| ReadQueryError::Invalid)?;
    let cursor_query = crate::cursor::CursorQuery {
        projection: projection.iter().map(cursor_projection_from_read).collect(),
        filter: filter.as_ref().map(cursor_filter_expr_from_read),
        spatial: spatial.as_ref().map(cursor_spatial_from_read),
        order: order.as_ref().map(cursor_order_from_read),
        include_count,
        page_size,
        temporal_instant: temporal_instant.clone(),
        scope,
    };
    Ok(Some(CompiledReadQuery {
        route_id: route.id.clone(),
        query_operation_id: operation.id.clone(),
        kind,
        cursor_binding: binding,
        cursor_query,
        projection,
        filter,
        spatial,
        order,
        include_count,
        page_size,
        temporal_instant,
        adapter,
        adapter_origin,
        continuation: None,
    }))
}

fn query_operation_for_route<'a>(
    service: &'a HttpService,
    route: &CompiledRoute,
    surface: &AuthorizedSurface<'_>,
    kind: CompiledQueryKind,
) -> Option<&'a CompiledQueryOperation> {
    service
        .registry
        .queries()
        .operations
        .iter()
        .find(|operation| {
            operation.route_id == route.id
                && operation.entity_id == surface.response_entity.id
                && operation.profile_id == surface.context.selected_profile()
                && operation.kind == kind
        })
}

fn lookup_query_operation_for_selector<'a>(
    service: &'a HttpService,
    route: &CompiledRoute,
    surface: &AuthorizedSurface<'_>,
    selector_id: &str,
) -> Option<&'a CompiledQueryOperation> {
    let selector = surface.entity.selector_profiles.get(selector_id)?;
    service
        .registry
        .queries()
        .operations
        .iter()
        .find(|operation| {
            operation.route_id == route.id
                && operation.entity_id == surface.entity.id
                && operation.profile_id == surface.context.selected_profile()
                && operation.kind == CompiledQueryKind::List
                && operation.read_path.is_none()
                && operation.selector_fields == selector.fields
        })
}

fn cursor_scope(
    surface: &AuthorizedSurface<'_>,
    root_id: Option<&str>,
) -> Result<CursorQueryScope, ReadQueryError> {
    match surface.read_path {
        Some(read_path) => {
            let root_id = root_id.ok_or(ReadQueryError::Invalid)?;
            if !valid_canonical_record_uuid(root_id) {
                return Err(ReadQueryError::Invalid);
            }
            Ok(CursorQueryScope::Relationship {
                path_id: read_path.id.clone(),
                root_id: root_id.to_owned(),
            })
        }
        None => Ok(CursorQueryScope::Collection {}),
    }
}

fn resolve_select(
    entity: &CompiledEntity,
    readable_fields: &BTreeSet<String>,
    select: Option<&strict_query::SelectClause>,
) -> Result<Option<BTreeSet<String>>, ()> {
    let Some(select) = select else {
        return Ok(None);
    };
    let mut fields = BTreeSet::new();
    for field in select.fields() {
        let field_id = resolve_data_field_id(entity, field.as_str()).ok_or(())?;
        if !readable_fields.contains(field_id) {
            return Err(());
        }
        fields.insert(field_id.to_owned());
    }
    if fields.is_empty() {
        Ok(None)
    } else {
        Ok(Some(fields))
    }
}

fn resolve_data_field_id<'a>(entity: &'a CompiledEntity, api_name: &str) -> Option<&'a str> {
    entity
        .stored_fields
        .iter()
        .map(|field| &field.logical)
        .chain(entity.derived_fields.values().map(|field| &field.logical))
        .find(|field| field.api_name == api_name)
        .map(|field| field.id.as_str())
}

fn projection_plan(
    entity: &CompiledEntity,
    selected_fields: &BTreeSet<String>,
) -> Result<Vec<ReadProjectionField>, ReadQueryError> {
    selected_fields
        .iter()
        .map(|field_id| {
            let field_type = data_field_type(entity, field_id).ok_or(ReadQueryError::Invalid)?;
            Ok(ReadProjectionField {
                field_id: field_id.clone(),
                field_type: field_type.clone(),
            })
        })
        .collect()
}

fn data_field_type<'a>(entity: &'a CompiledEntity, field_id: &str) -> Option<&'a FieldTypeSource> {
    entity
        .fields
        .get(field_id)
        .map(|field| &field.field_type)
        .or_else(|| {
            entity
                .derived_fields
                .get(field_id)
                .map(|field| &field.logical.field_type)
        })
}

fn resolve_query_field_id(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    api_name: &str,
) -> Option<String> {
    if let Some(field_id) = resolve_data_field_id(entity, api_name) {
        if operation
            .filter_fields
            .iter()
            .any(|field| field.field == field_id)
            || operation
                .sort_fields
                .iter()
                .any(|field| field.field == field_id)
        {
            return Some(field_id.to_owned());
        }
    }
    let request_field = request_query_field_id_for_api(api_name)?;
    if entity.change_request.is_some()
        && (operation
            .filter_fields
            .iter()
            .any(|field| field.field == request_field)
            || operation
                .sort_fields
                .iter()
                .any(|field| field.field == request_field))
    {
        Some(request_field.to_owned())
    } else {
        None
    }
}

fn query_field_type(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    field_id: &str,
) -> Option<FieldTypeSource> {
    if operation
        .projection_fields
        .iter()
        .any(|field| field == field_id)
        || operation
            .filter_fields
            .iter()
            .any(|field| field.field == field_id)
        || operation
            .sort_fields
            .iter()
            .any(|field| field.field == field_id)
    {
        data_field_type(entity, field_id).cloned().or_else(|| {
            entity
                .change_request
                .as_ref()
                .and_then(|_| request_query_field_type(field_id))
        })
    } else {
        None
    }
}

fn first_page_filter_expr(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    filter: Option<&strict_query::FilterExpr>,
) -> Result<Option<ReadFilterExpr>, ReadQueryError> {
    filter
        .map(|filter| read_filter_expr(entity, operation, filter))
        .transpose()
}

fn first_page_spatial_query(
    surface: &AuthorizedSurface<'_>,
    operation: &CompiledQueryOperation,
    bbox: Option<&strict_query::BboxClause>,
) -> Result<Option<ReadSpatialQuery>, ReadQueryError> {
    let Some(bbox) = bbox else {
        return Ok(None);
    };
    if surface.read_path.is_some() || operation.kind != CompiledQueryKind::List {
        return Err(ReadQueryError::Invalid);
    }
    let capability = operation
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
        .ok_or(ReadQueryError::Invalid)?;
    if !surface.readable_fields.contains(&capability.geometry_field) {
        return Err(ReadQueryError::Invalid);
    }
    let Some(geojson) = surface.response_entity.geojson.as_ref() else {
        return Err(ReadQueryError::Invalid);
    };
    if geojson.geometry_field != capability.geometry_field {
        return Err(ReadQueryError::Invalid);
    }
    if !matches!(
        data_field_type(surface.response_entity, &capability.geometry_field),
        Some(FieldTypeSource::Crs84Point { .. })
    ) {
        return Err(ReadQueryError::Invalid);
    }
    let maximum_longitude_span =
        maximum_span_text(&capability.maximum_longitude_span_degrees, "360")?;
    let maximum_latitude_span =
        maximum_span_text(&capability.maximum_latitude_span_degrees, "180")?;
    if !decimal_difference_within(bbox.east(), bbox.west(), &maximum_longitude_span)?
        || !decimal_difference_within(bbox.north(), bbox.south(), &maximum_latitude_span)?
    {
        return Err(ReadQueryError::Invalid);
    }
    Ok(Some(ReadSpatialQuery {
        bbox: ReadBboxQuery {
            geometry_field: capability.geometry_field.clone(),
            west: bbox.west().to_owned(),
            south: bbox.south().to_owned(),
            east: bbox.east().to_owned(),
            north: bbox.north().to_owned(),
            maximum_longitude_span_degrees: maximum_longitude_span,
            maximum_latitude_span_degrees: maximum_latitude_span,
        },
    }))
}

fn read_spatial_from_cursor(
    operation: &CompiledQueryOperation,
    spatial: &CursorSpatialQuery,
) -> Result<ReadSpatialQuery, ReadQueryError> {
    let capability = operation
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
        .ok_or(ReadQueryError::Invalid)?;
    let maximum_longitude_span =
        maximum_span_text(&capability.maximum_longitude_span_degrees, "360")?;
    let maximum_latitude_span =
        maximum_span_text(&capability.maximum_latitude_span_degrees, "180")?;
    if spatial.bbox.geometry_field != capability.geometry_field
        || spatial.bbox.maximum_longitude_span_degrees != maximum_longitude_span
        || spatial.bbox.maximum_latitude_span_degrees != maximum_latitude_span
    {
        return Err(ReadQueryError::Invalid);
    }
    Ok(ReadSpatialQuery {
        bbox: ReadBboxQuery {
            geometry_field: spatial.bbox.geometry_field.clone(),
            west: spatial.bbox.west.clone(),
            south: spatial.bbox.south.clone(),
            east: spatial.bbox.east.clone(),
            north: spatial.bbox.north.clone(),
            maximum_longitude_span_degrees: spatial.bbox.maximum_longitude_span_degrees.clone(),
            maximum_latitude_span_degrees: spatial.bbox.maximum_latitude_span_degrees.clone(),
        },
    })
}

fn maximum_span_text(value: &serde_json::Number, upper: &str) -> Result<String, ReadQueryError> {
    strict_query::canonical_positive_decimal_within(&value.to_string(), upper)
        .map_err(|_| ReadQueryError::Invalid)
}

fn decimal_difference_within(
    upper: &str,
    lower: &str,
    maximum: &str,
) -> Result<bool, ReadQueryError> {
    strict_query::decimal_difference_within(upper, lower, maximum)
        .map_err(|_| ReadQueryError::Invalid)
}

fn read_filter_expr(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    filter: &strict_query::FilterExpr,
) -> Result<ReadFilterExpr, ReadQueryError> {
    match filter {
        strict_query::FilterExpr::Binary { op, left, right } => Ok(ReadFilterExpr::Binary {
            op: match op {
                strict_query::LogicalOp::And => ReadLogicalOp::And,
                strict_query::LogicalOp::Or => ReadLogicalOp::Or,
            },
            left: Box::new(read_filter_expr(entity, operation, left)?),
            right: Box::new(read_filter_expr(entity, operation, right)?),
        }),
        strict_query::FilterExpr::Not(expr) => Ok(ReadFilterExpr::Not(Box::new(read_filter_expr(
            entity, operation, expr,
        )?))),
        strict_query::FilterExpr::Group(expr) => Ok(ReadFilterExpr::Group(Box::new(
            read_filter_expr(entity, operation, expr)?,
        ))),
        strict_query::FilterExpr::Predicate(predicate) => Ok(ReadFilterExpr::Predicate(
            read_filter_predicate(entity, operation, predicate)?,
        )),
    }
}

fn read_filter_predicate(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    predicate: &strict_query::FilterPredicate,
) -> Result<ReadFilterPredicate, ReadQueryError> {
    let (api_field, operator, literals) = match predicate {
        strict_query::FilterPredicate::Compare { field, op, literal } => match (op, literal) {
            (strict_query::ComparisonOp::Eq, strict_query::Literal::Null) => {
                (field.as_str(), ReadFilterOperator::IsNull, Vec::new())
            }
            (strict_query::ComparisonOp::Ne, strict_query::Literal::Null) => {
                (field.as_str(), ReadFilterOperator::IsNotNull, Vec::new())
            }
            (strict_query::ComparisonOp::Eq, literal) => {
                (field.as_str(), ReadFilterOperator::Eq, vec![literal])
            }
            (strict_query::ComparisonOp::Ne, literal) => {
                (field.as_str(), ReadFilterOperator::Ne, vec![literal])
            }
            (strict_query::ComparisonOp::Lt, literal) => {
                (field.as_str(), ReadFilterOperator::Lt, vec![literal])
            }
            (strict_query::ComparisonOp::Le, literal) => {
                (field.as_str(), ReadFilterOperator::Le, vec![literal])
            }
            (strict_query::ComparisonOp::Gt, literal) => {
                (field.as_str(), ReadFilterOperator::Gt, vec![literal])
            }
            (strict_query::ComparisonOp::Ge, literal) => {
                (field.as_str(), ReadFilterOperator::Ge, vec![literal])
            }
        },
        strict_query::FilterPredicate::In { field, values } => (
            field.as_str(),
            ReadFilterOperator::In,
            values.iter().collect::<Vec<_>>(),
        ),
        strict_query::FilterPredicate::Function {
            function,
            field,
            literal,
        } => {
            let operator = match function {
                strict_query::StringFunction::StartsWith => ReadFilterOperator::StartsWith,
                strict_query::StringFunction::Contains => ReadFilterOperator::Contains,
            };
            (field.as_str(), operator, vec![literal])
        }
    };
    let field_id =
        resolve_query_field_id(entity, operation, api_field).ok_or(ReadQueryError::Invalid)?;
    let field_type =
        query_field_type(entity, operation, &field_id).ok_or(ReadQueryError::Invalid)?;
    let capability = operation
        .filter_fields
        .iter()
        .find(|candidate| candidate.field == field_id)
        .ok_or(ReadQueryError::Invalid)?;
    if !capability
        .operators
        .contains(&operator.compiled_capability())
    {
        return Err(ReadQueryError::Invalid);
    }
    let mut values = if matches!(
        operator,
        ReadFilterOperator::IsNull | ReadFilterOperator::IsNotNull
    ) {
        vec!["true".to_owned()]
    } else {
        literals
            .into_iter()
            .map(|literal| literal_to_field_value(literal, &field_type))
            .collect::<Result<Vec<_>, _>>()?
    };
    if operator == ReadFilterOperator::In {
        let unique = values.iter().collect::<BTreeSet<_>>();
        if values.is_empty() || values.len() > MAX_IN_VALUES || unique.len() != values.len() {
            return Err(ReadQueryError::Invalid);
        }
        values.sort();
    }
    Ok(ReadFilterPredicate {
        field_id,
        field_type,
        operator,
        values,
    })
}

fn literal_to_field_value(
    literal: &strict_query::Literal,
    field_type: &FieldTypeSource,
) -> Result<String, ReadQueryError> {
    let value = match literal {
        strict_query::Literal::String(value)
        | strict_query::Literal::Integer(value)
        | strict_query::Literal::Decimal(value) => value.clone(),
        strict_query::Literal::Boolean(value) => value.to_string(),
        strict_query::Literal::Null => return Err(ReadQueryError::Invalid),
    };
    crate::postgres::validate_field_value(&value, field_type)
        .map_err(|_| ReadQueryError::Invalid)?;
    Ok(value)
}

fn resolve_order_clause(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    orderby: &strict_query::OrderByClause,
) -> Result<ReadOrderClause, ReadQueryError> {
    read_order_clause(entity, operation, Some(orderby.field.as_str()))?
        .ok_or(ReadQueryError::Invalid)
}

fn read_order_clause(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    api_or_field: Option<&str>,
) -> Result<Option<ReadOrderClause>, ReadQueryError> {
    let Some(api_or_field) = api_or_field else {
        return Ok(None);
    };
    let field_id =
        resolve_query_field_id(entity, operation, api_or_field).ok_or(ReadQueryError::Invalid)?;
    let field_type =
        query_field_type(entity, operation, &field_id).ok_or(ReadQueryError::Invalid)?;
    let sortable = operation.sort_fields.iter().any(|candidate| {
        candidate.field == field_id
            && candidate
                .directions
                .contains(&CompiledQuerySortDirection::Asc)
    });
    if !sortable {
        return Err(ReadQueryError::Invalid);
    }
    Ok(Some(ReadOrderClause {
        field_id,
        field_type,
        direction: CompiledQuerySortDirection::Asc,
    }))
}

fn validate_query_shape(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    filter: Option<&ReadFilterExpr>,
    spatial: Option<&ReadSpatialQuery>,
    order: Option<&ReadOrderClause>,
    page_size: u16,
) -> Result<(), ReadQueryError> {
    if page_size == 0 || page_size > operation.max_page_size {
        return Err(ReadQueryError::Invalid);
    }
    let mut stats = QueryShapeStats::default();
    if let Some(filter) = filter {
        validate_filter_shape(entity, operation, filter, &mut stats)?;
        if stats.predicates > MAX_FILTER_CLAUSES || stats.in_values > MAX_IN_VALUES {
            return Err(ReadQueryError::Invalid);
        }
    }
    if let Some(spatial) = spatial {
        validate_spatial_shape(entity, operation, spatial)?;
    }
    if let Some(order) = order {
        let sortable = operation.sort_fields.iter().any(|field| {
            field.field == order.field_id
                && field.directions.contains(&CompiledQuerySortDirection::Asc)
        });
        if !sortable
            || operation.stable_tie_breaker != "record_id"
            || order.direction != CompiledQuerySortDirection::Asc
            || query_field_type(entity, operation, &order.field_id)
                != Some(order.field_type.clone())
        {
            return Err(ReadQueryError::Invalid);
        }
    }
    Ok(())
}

fn validate_spatial_shape(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    spatial: &ReadSpatialQuery,
) -> Result<(), ReadQueryError> {
    let capability = operation
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
        .ok_or(ReadQueryError::Invalid)?;
    let maximum_longitude_span =
        maximum_span_text(&capability.maximum_longitude_span_degrees, "360")?;
    let maximum_latitude_span =
        maximum_span_text(&capability.maximum_latitude_span_degrees, "180")?;
    if spatial.bbox.geometry_field != capability.geometry_field
        || spatial.bbox.maximum_longitude_span_degrees != maximum_longitude_span
        || spatial.bbox.maximum_latitude_span_degrees != maximum_latitude_span
        || !matches!(
            data_field_type(entity, &spatial.bbox.geometry_field),
            Some(FieldTypeSource::Crs84Point { .. })
        )
    {
        return Err(ReadQueryError::Invalid);
    }
    let parsed = strict_query::parse_read_query([(
        "bbox",
        format!(
            "{},{},{},{}",
            spatial.bbox.west, spatial.bbox.south, spatial.bbox.east, spatial.bbox.north
        ),
    )])
    .map_err(|_| ReadQueryError::Invalid)?;
    let strict_query::ParsedReadQueryMode::Query(options) = parsed.mode else {
        return Err(ReadQueryError::Invalid);
    };
    let bbox = options.bbox.ok_or(ReadQueryError::Invalid)?;
    if !decimal_difference_within(bbox.east(), bbox.west(), &maximum_longitude_span)?
        || !decimal_difference_within(bbox.north(), bbox.south(), &maximum_latitude_span)?
    {
        return Err(ReadQueryError::Invalid);
    }
    Ok(())
}

#[derive(Default)]
struct QueryShapeStats {
    predicates: usize,
    in_values: usize,
}

fn validate_filter_shape(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    filter: &ReadFilterExpr,
    stats: &mut QueryShapeStats,
) -> Result<(), ReadQueryError> {
    match filter {
        ReadFilterExpr::Binary { left, right, .. } => {
            validate_filter_shape(entity, operation, left, stats)?;
            validate_filter_shape(entity, operation, right, stats)
        }
        ReadFilterExpr::Not(expr) | ReadFilterExpr::Group(expr) => {
            validate_filter_shape(entity, operation, expr, stats)
        }
        ReadFilterExpr::Predicate(predicate) => {
            stats.predicates = stats
                .predicates
                .checked_add(1)
                .ok_or(ReadQueryError::Invalid)?;
            let field_type = query_field_type(entity, operation, &predicate.field_id)
                .ok_or(ReadQueryError::Invalid)?;
            let capability = operation
                .filter_fields
                .iter()
                .find(|field| field.field == predicate.field_id)
                .ok_or(ReadQueryError::Invalid)?;
            if field_type != predicate.field_type
                || !capability
                    .operators
                    .contains(&predicate.operator.compiled_capability())
            {
                return Err(ReadQueryError::Invalid);
            }
            match predicate.operator {
                ReadFilterOperator::Eq
                | ReadFilterOperator::Ne
                | ReadFilterOperator::Lt
                | ReadFilterOperator::Le
                | ReadFilterOperator::Gt
                | ReadFilterOperator::Ge
                | ReadFilterOperator::StartsWith
                | ReadFilterOperator::Contains => {
                    if predicate.values.len() != 1 {
                        return Err(ReadQueryError::Invalid);
                    }
                    crate::postgres::validate_field_value(&predicate.values[0], &field_type)
                        .map_err(|_| ReadQueryError::Invalid)?;
                }
                ReadFilterOperator::In => {
                    if predicate.values.is_empty()
                        || predicate
                            .values
                            .windows(2)
                            .any(|window| window[0] >= window[1])
                    {
                        return Err(ReadQueryError::Invalid);
                    }
                    stats.in_values = stats
                        .in_values
                        .checked_add(predicate.values.len())
                        .ok_or(ReadQueryError::Invalid)?;
                    for value in &predicate.values {
                        crate::postgres::validate_field_value(value, &field_type)
                            .map_err(|_| ReadQueryError::Invalid)?;
                    }
                }
                ReadFilterOperator::IsNull | ReadFilterOperator::IsNotNull => {
                    if predicate.values.as_slice() != ["true"] {
                        return Err(ReadQueryError::Invalid);
                    }
                }
            }
            Ok(())
        }
    }
}

fn temporal_instant_for(
    kind: CompiledQueryKind,
    options: &QueryOptions,
    entity: &CompiledEntity,
) -> Result<Option<String>, ReadQueryError> {
    match kind {
        CompiledQueryKind::List => {
            if options.parsed.as_of.is_some() {
                return Err(ReadQueryError::Invalid);
            }
            Ok(None)
        }
        CompiledQueryKind::Current => {
            if options.parsed.as_of.is_some() {
                return Err(ReadQueryError::Invalid);
            }
            OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map(Some)
                .map_err(|_| ReadQueryError::Invalid)
        }
        CompiledQueryKind::AsOf => {
            let value = options
                .parsed
                .as_of
                .as_deref()
                .ok_or(ReadQueryError::Invalid)?;
            parse_strict_rfc3339_utc(value).map_err(|_| ReadQueryError::Invalid)?;
            Ok(Some(value.to_owned()))
        }
        CompiledQueryKind::Snapshot => options
            .historical
            .as_ref()
            .ok_or(ReadQueryError::Invalid)?
            .valid_at
            .as_deref()
            .map(|value| {
                normalize_history_valid_at(entity, value).map_err(|_| ReadQueryError::Invalid)
            })
            .transpose(),
    }
}

/// Date and timestamp histories have distinct input types. There is no clock
/// default, date truncation, local-time inference, or offset conversion.
pub(crate) fn normalize_history_valid_at(
    entity: &CompiledEntity,
    value: &str,
) -> Result<String, ()> {
    let temporal = entity.temporal.as_ref().ok_or(())?;
    let field = entity.fields.get(&temporal.start_field).ok_or(())?;
    match &field.field_type {
        FieldTypeSource::Date => {
            if value.len() != 10 {
                return Err(());
            }
            let format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
                .map_err(|_| ())?;
            let parsed = time::Date::parse(value, &format).map_err(|_| ())?;
            let normalized = parsed.format(&format).map_err(|_| ())?;
            if normalized != value {
                return Err(());
            }
            Ok(normalized)
        }
        FieldTypeSource::Timestamp => {
            let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ())?;
            if parsed.offset() != time::UtcOffset::UTC {
                return Err(());
            }
            parsed.format(&Rfc3339).map_err(|_| ())
        }
        _ => Err(()),
    }
}

fn parse_strict_rfc3339_utc(value: &str) -> Result<OffsetDateTime, ()> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ())?;
    if parsed.offset() != time::UtcOffset::UTC || parsed.format(&Rfc3339).map_err(|_| ())? != value
    {
        return Err(());
    }
    Ok(parsed)
}

fn cursor_binding(
    service: &HttpService,
    route: &CompiledRoute,
    surface: &AuthorizedSurface<'_>,
    operation: &CompiledQueryOperation,
    query: CursorBindingQuery<'_>,
) -> Result<CursorBinding, CursorError> {
    let selected_fields_vec = query.selected_fields.iter().cloned().collect::<Vec<_>>();
    let references = crate::query_binding::references(
        &service.cursors,
        &route.id,
        operation,
        &surface.context,
        query,
    )?;
    Ok(CursorBinding {
        package_revision: service.identity.package_revision.clone(),
        schema_fingerprint: service.identity.schema_fingerprint.clone(),
        registry_revision: service.registry.revision().to_owned(),
        route_id: route.id.clone(),
        query_operation_id: operation.id.clone(),
        query_kind: operation.kind,
        selected_profile: surface.context.selected_profile().to_owned(),
        principal_reference: references.principal,
        purpose_reference: references.purpose,
        row_boundary_reference: references.row_boundary,
        projection_reference: references.projection,
        query_reference: references.query,
        sort_reference: references.sort,
        scope_reference: references.scope,
        spatial_reference: references.spatial,
        representation: query.representation,
        adapter: query.adapter,
        page_size: query.page_size,
        include_count: query.include_count,
        temporal_instant: query.temporal_instant.map(str::to_owned),
        selected_fields: selected_fields_vec,
    })
}

fn cursor_adapter_origin(
    service: &HttpService,
    adapter: CursorAdapter,
) -> Result<Option<String>, CursorError> {
    match adapter {
        CursorAdapter::Native => Ok(None),
        CursorAdapter::Gis => service
            .public_origin
            .as_ref()
            .map(|origin| origin.as_str().to_owned())
            .map(Some)
            .ok_or(CursorError::Mismatch),
    }
}

fn cursor_spatial_from_read(spatial: &ReadSpatialQuery) -> CursorSpatialQuery {
    CursorSpatialQuery {
        bbox: CursorBboxQuery {
            geometry_field: spatial.bbox.geometry_field.clone(),
            west: spatial.bbox.west.clone(),
            south: spatial.bbox.south.clone(),
            east: spatial.bbox.east.clone(),
            north: spatial.bbox.north.clone(),
            maximum_longitude_span_degrees: spatial.bbox.maximum_longitude_span_degrees.clone(),
            maximum_latitude_span_degrees: spatial.bbox.maximum_latitude_span_degrees.clone(),
        },
    }
}

fn cursor_projection_from_read(field: &ReadProjectionField) -> CursorProjectionField {
    CursorProjectionField {
        field_id: field.field_id.clone(),
        field_type: field.field_type.clone(),
    }
}

fn cursor_order_from_read(order: &ReadOrderClause) -> CursorOrderClause {
    CursorOrderClause {
        field_id: order.field_id.clone(),
        field_type: order.field_type.clone(),
        direction: order.direction,
    }
}

fn cursor_filter_expr_from_read(filter: &ReadFilterExpr) -> CursorFilterExpr {
    match filter {
        ReadFilterExpr::Binary { op, left, right } => CursorFilterExpr::Binary {
            op: match op {
                ReadLogicalOp::And => CursorLogicalOp::And,
                ReadLogicalOp::Or => CursorLogicalOp::Or,
            },
            left: Box::new(cursor_filter_expr_from_read(left)),
            right: Box::new(cursor_filter_expr_from_read(right)),
        },
        ReadFilterExpr::Not(expr) => CursorFilterExpr::Not {
            expr: Box::new(cursor_filter_expr_from_read(expr)),
        },
        ReadFilterExpr::Group(expr) => CursorFilterExpr::Group {
            expr: Box::new(cursor_filter_expr_from_read(expr)),
        },
        ReadFilterExpr::Predicate(predicate) => CursorFilterExpr::Predicate {
            predicate: CursorFilterPredicate {
                field_id: predicate.field_id.clone(),
                field_type: predicate.field_type.clone(),
                operator: cursor_operator_from_read(predicate.operator),
                values: predicate.values.clone(),
            },
        },
    }
}

fn read_projection_from_cursor(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    selected_fields: &BTreeSet<String>,
    projection: &[CursorProjectionField],
) -> Result<Vec<ReadProjectionField>, ReadQueryError> {
    if projection.len() != selected_fields.len() {
        return Err(ReadQueryError::CursorInvalid);
    }
    let expected = projection_plan(entity, selected_fields)?;
    let actual = projection
        .iter()
        .map(|field| {
            if !operation.projection_fields.contains(&field.field_id) {
                return Err(ReadQueryError::CursorInvalid);
            }
            Ok(ReadProjectionField {
                field_id: field.field_id.clone(),
                field_type: field.field_type.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if actual != expected {
        return Err(ReadQueryError::CursorInvalid);
    }
    Ok(actual)
}

fn read_order_clause_from_cursor(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    order: &CursorOrderClause,
) -> Result<ReadOrderClause, ReadQueryError> {
    let field_type = query_field_type(entity, operation, &order.field_id)
        .ok_or(ReadQueryError::CursorInvalid)?;
    let sortable = operation.sort_fields.iter().any(|candidate| {
        candidate.field == order.field_id
            && candidate
                .directions
                .contains(&CompiledQuerySortDirection::Asc)
    });
    if !sortable
        || field_type != order.field_type
        || order.direction != CompiledQuerySortDirection::Asc
    {
        return Err(ReadQueryError::CursorInvalid);
    }
    Ok(ReadOrderClause {
        field_id: order.field_id.clone(),
        field_type: order.field_type.clone(),
        direction: order.direction,
    })
}

fn read_filter_expr_from_cursor(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    filter: &CursorFilterExpr,
) -> Result<ReadFilterExpr, ReadQueryError> {
    match filter {
        CursorFilterExpr::Binary { op, left, right } => Ok(ReadFilterExpr::Binary {
            op: match op {
                CursorLogicalOp::And => ReadLogicalOp::And,
                CursorLogicalOp::Or => ReadLogicalOp::Or,
            },
            left: Box::new(read_filter_expr_from_cursor(entity, operation, left)?),
            right: Box::new(read_filter_expr_from_cursor(entity, operation, right)?),
        }),
        CursorFilterExpr::Not { expr } => Ok(ReadFilterExpr::Not(Box::new(
            read_filter_expr_from_cursor(entity, operation, expr)?,
        ))),
        CursorFilterExpr::Group { expr } => Ok(ReadFilterExpr::Group(Box::new(
            read_filter_expr_from_cursor(entity, operation, expr)?,
        ))),
        CursorFilterExpr::Predicate { predicate } => {
            let field_type = query_field_type(entity, operation, &predicate.field_id)
                .ok_or(ReadQueryError::CursorInvalid)?;
            if field_type != predicate.field_type {
                return Err(ReadQueryError::CursorInvalid);
            }
            Ok(ReadFilterExpr::Predicate(ReadFilterPredicate {
                field_id: predicate.field_id.clone(),
                field_type: predicate.field_type.clone(),
                operator: read_operator_from_cursor(predicate.operator),
                values: predicate.values.clone(),
            }))
        }
    }
}

fn cursor_operator_from_read(operator: ReadFilterOperator) -> CursorFilterOperator {
    match operator {
        ReadFilterOperator::Eq => CursorFilterOperator::Eq,
        ReadFilterOperator::Ne => CursorFilterOperator::Ne,
        ReadFilterOperator::Lt => CursorFilterOperator::Lt,
        ReadFilterOperator::Le => CursorFilterOperator::Le,
        ReadFilterOperator::Gt => CursorFilterOperator::Gt,
        ReadFilterOperator::Ge => CursorFilterOperator::Ge,
        ReadFilterOperator::In => CursorFilterOperator::In,
        ReadFilterOperator::IsNull => CursorFilterOperator::IsNull,
        ReadFilterOperator::IsNotNull => CursorFilterOperator::IsNotNull,
        ReadFilterOperator::StartsWith => CursorFilterOperator::StartsWith,
        ReadFilterOperator::Contains => CursorFilterOperator::Contains,
    }
}

fn read_operator_from_cursor(operator: CursorFilterOperator) -> ReadFilterOperator {
    match operator {
        CursorFilterOperator::Eq => ReadFilterOperator::Eq,
        CursorFilterOperator::Ne => ReadFilterOperator::Ne,
        CursorFilterOperator::Lt => ReadFilterOperator::Lt,
        CursorFilterOperator::Le => ReadFilterOperator::Le,
        CursorFilterOperator::Gt => ReadFilterOperator::Gt,
        CursorFilterOperator::Ge => ReadFilterOperator::Ge,
        CursorFilterOperator::In => ReadFilterOperator::In,
        CursorFilterOperator::IsNull => ReadFilterOperator::IsNull,
        CursorFilterOperator::IsNotNull => ReadFilterOperator::IsNotNull,
        CursorFilterOperator::StartsWith => ReadFilterOperator::StartsWith,
        CursorFilterOperator::Contains => ReadFilterOperator::Contains,
    }
}

struct LookupBody {
    selector_id: String,
    values: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupResolutionError {
    InvalidRequest,
    Unresolved,
}

fn parse_lookup_body(body: &[u8]) -> Result<LookupBody, ()> {
    let value = parse_json_strict(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    let selector_id = object.get("selector").and_then(Value::as_str).ok_or(())?;
    if selector_id.is_empty() {
        return Err(());
    }
    let values = match object.get("values") {
        Some(Value::Object(values)) => Some(
            values
                .iter()
                .map(|(field, value)| (field.clone(), value.clone()))
                .collect(),
        ),
        Some(_) => return Err(()),
        None => None,
    };
    let expected_len = if values.is_some() { 2 } else { 1 };
    if object.len() != expected_len {
        return Err(());
    }
    Ok(LookupBody {
        selector_id: selector_id.to_owned(),
        values,
    })
}

fn resolve_lookup_selector(
    service: &HttpService,
    route: &CompiledRoute,
    surface: &AuthorizedSurface<'_>,
    claims: &VerifiedRequestClaims,
    body: &LookupBody,
) -> Result<CompiledLookupSelector, LookupResolutionError> {
    let selector = surface
        .entity
        .selector_profiles
        .get(&body.selector_id)
        .ok_or(LookupResolutionError::Unresolved)?;
    let profile = surface
        .entity
        .access_profiles
        .get(surface.context.selected_profile())
        .ok_or(LookupResolutionError::Unresolved)?;
    let grant = profile
        .lookups
        .iter()
        .find(|lookup| lookup.selector == body.selector_id)
        .ok_or(LookupResolutionError::Unresolved)?;
    let operation = lookup_query_operation_for_selector(service, route, surface, &body.selector_id)
        .ok_or(LookupResolutionError::Unresolved)?;
    let values = match grant.value_origin {
        LookupValueOrigin::Request => {
            let values = body
                .values
                .as_ref()
                .ok_or(LookupResolutionError::InvalidRequest)?;
            lookup_request_values(surface.entity, selector, values)?
        }
        LookupValueOrigin::VerifiedClaim => {
            if body.values.is_some() {
                return Err(LookupResolutionError::InvalidRequest);
            }
            lookup_verified_claim_values(surface.entity, selector, grant, claims)?
        }
    };
    Ok(CompiledLookupSelector {
        route_id: route.id.clone(),
        query_operation_id: operation.id.clone(),
        selector_id: selector.id.clone(),
        value_origin: grant.value_origin,
        values,
    })
}

fn lookup_request_values(
    entity: &CompiledEntity,
    selector: &crate::model::CompiledSelectorProfile,
    values: &BTreeMap<String, Value>,
) -> Result<Vec<LookupSelectorValue>, LookupResolutionError> {
    let expected = selector
        .fields
        .iter()
        .map(|field_id| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == *field_id)
                .map(|field| field.logical.api_name.as_str())
                .ok_or(LookupResolutionError::Unresolved)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(LookupResolutionError::InvalidRequest);
    }
    selector
        .fields
        .iter()
        .map(|field_id| {
            let field = entity
                .fields
                .get(field_id)
                .ok_or(LookupResolutionError::Unresolved)?;
            let api_name = entity
                .stored_fields
                .iter()
                .find(|stored| stored.logical.id == *field_id)
                .map(|stored| stored.logical.api_name.as_str())
                .ok_or(LookupResolutionError::Unresolved)?;
            let value = lookup_json_scalar(
                values
                    .get(api_name)
                    .ok_or(LookupResolutionError::InvalidRequest)?,
                &field.field_type,
            )?;
            Ok(LookupSelectorValue {
                field_id: field_id.clone(),
                field_type: field.field_type.clone(),
                value,
            })
        })
        .collect()
}

fn lookup_verified_claim_values(
    entity: &CompiledEntity,
    selector: &crate::model::CompiledSelectorProfile,
    grant: &crate::contract::LookupGrantSource,
    claims: &VerifiedRequestClaims,
) -> Result<Vec<LookupSelectorValue>, LookupResolutionError> {
    selector
        .fields
        .iter()
        .map(|field_id| {
            let field = entity
                .fields
                .get(field_id)
                .ok_or(LookupResolutionError::Unresolved)?;
            let claim_name = grant
                .claim_mapping
                .get(field_id)
                .ok_or(LookupResolutionError::Unresolved)?;
            let claim = claims
                .direct_claim(claim_name)
                .ok_or(LookupResolutionError::Unresolved)?;
            let values = claim.values();
            if values.len() != 1 {
                return Err(LookupResolutionError::Unresolved);
            }
            let value = values
                .into_iter()
                .next()
                .ok_or(LookupResolutionError::Unresolved)?;
            crate::postgres::validate_field_value(&value, &field.field_type)
                .map_err(|_| LookupResolutionError::Unresolved)?;
            Ok(LookupSelectorValue {
                field_id: field_id.clone(),
                field_type: field.field_type.clone(),
                value,
            })
        })
        .collect()
}

fn lookup_json_scalar(
    value: &Value,
    field_type: &FieldTypeSource,
) -> Result<String, LookupResolutionError> {
    let value = match field_type {
        FieldTypeSource::Boolean => value
            .as_bool()
            .map(|value| value.to_string())
            .ok_or(LookupResolutionError::InvalidRequest)?,
        FieldTypeSource::Int64 => value
            .as_i64()
            .map(|value| value.to_string())
            .ok_or(LookupResolutionError::InvalidRequest)?,
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp
        | FieldTypeSource::Uuid
        | FieldTypeSource::Reference { .. }
        | FieldTypeSource::VocabularyCode { .. } => value
            .as_str()
            .map(str::to_owned)
            .ok_or(LookupResolutionError::InvalidRequest)?,
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            return Err(LookupResolutionError::InvalidRequest);
        }
    };
    crate::postgres::validate_field_value(&value, field_type)
        .map_err(|_| LookupResolutionError::InvalidRequest)?;
    Ok(value)
}

fn filtered_schema(
    service: &HttpService,
    entity_id: &str,
    readable_fields: &BTreeSet<String>,
    permitted_requests: &BTreeSet<String>,
) -> Option<Value> {
    let entity = service.registry.entities().get(entity_id)?;
    let readable_api_names = entity
        .stored_fields
        .iter()
        .map(|field| &field.logical)
        .chain(entity.derived_fields.values().map(|field| &field.logical))
        .filter(|field| readable_fields.contains(&field.id))
        .map(|field| field.api_name.as_str())
        .collect::<BTreeSet<_>>();
    let path = format!("generated/schemas/{entity_id}.schema.json");
    let artifact = service.registry.artifacts().get(&path)?;
    let mut schema: Value = serde_json::from_slice(&artifact.bytes).ok()?;
    let object = schema.as_object_mut()?;
    let properties = object.get_mut("properties")?.as_object_mut()?;
    properties.retain(|field, _| readable_api_names.contains(field.as_str()));
    if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|field| {
            field
                .as_str()
                .is_some_and(|field| readable_api_names.contains(field))
        });
    }
    // Generated authoring artifacts contain complete effects and grants. The
    // served schema is a caller projection, so it must not copy that authority
    // inventory or identify request types hidden from the selected context.
    if let Some(control) = object.get_mut("x-registry-changeControl") {
        if let Some(types) = control
            .get_mut("eligibleRequestTypes")
            .and_then(Value::as_array_mut)
        {
            types.retain(|request_type| {
                request_type
                    .get("requestEntity")
                    .and_then(Value::as_str)
                    .is_some_and(|id| permitted_requests.contains(id))
            });
        }
    }
    if let Some(request) = object
        .get_mut("x-registry-changeRequest")
        .and_then(Value::as_object_mut)
    {
        request.retain(|key, _| matches!(key.as_str(), "requestEntity" | "stateEnvelope"));
    }
    Some(schema)
}

struct MetadataEntity {
    id: String,
    dataset_identifier: String,
    route: String,
    operations: BTreeMap<Operation, String>,
    readable_fields: BTreeSet<String>,
    schema_path: String,
    change_control: Option<Value>,
    change_request: Option<Value>,
}

struct QueryOptions {
    parsed: strict_query::ParsedReadQuery,
    request_history_after_proposal_version: Option<i64>,
    historical: Option<HistoricalQueryOptions>,
}

#[derive(Default)]
struct HistoricalQueryOptions {
    snapshot: Option<String>,
    valid_at: Option<String>,
}

impl QueryOptions {
    fn parse(raw: Option<&str>, allow_read_query: bool) -> Result<Self, QueryParseError> {
        let Some(raw) = raw else {
            return Ok(Self::default());
        };
        if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
            return Err(QueryParseError::Invalid);
        }
        let mut pairs = Vec::new();
        let mut request_history_after_proposal_version = None;
        for pair in raw.split('&') {
            let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
            let name = percent_decode(name)?;
            let value = percent_decode(value)?;
            if name == "requestHistoryAfterProposalVersion" {
                let version = value.parse::<u32>().map_err(|_| QueryParseError::Invalid)?;
                if version == 0
                    || version.to_string() != value
                    || request_history_after_proposal_version
                        .replace(i64::from(version))
                        .is_some()
                {
                    return Err(QueryParseError::Invalid);
                }
                continue;
            }
            pairs.push((name, value));
        }
        let parsed = strict_query::parse_read_query(pairs).map_err(|_| QueryParseError::Invalid)?;
        let result = Self {
            parsed,
            request_history_after_proposal_version,
            historical: None,
        };
        if result.request_history_after_proposal_version.is_some() && result.skiptoken().is_some() {
            return Err(QueryParseError::Invalid);
        }
        if !allow_read_query && result.has_any_query_member() {
            return Err(QueryParseError::Invalid);
        }
        Ok(result)
    }

    fn parse_snapshot(raw: Option<&str>) -> Result<Self, QueryParseError> {
        let mut pairs = Vec::new();
        if let Some(raw) = raw {
            if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
                return Err(QueryParseError::Invalid);
            }
            for pair in raw.split('&') {
                let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
                pairs.push((percent_decode(name)?, percent_decode(value)?));
            }
        }
        let parsed =
            strict_query::parse_snapshot_query(pairs).map_err(|_| QueryParseError::Invalid)?;
        Ok(Self {
            parsed: strict_query::ParsedReadQuery {
                access_profile: parsed.access_profile,
                as_of: None,
                mode: parsed.mode,
            },
            request_history_after_proposal_version: None,
            historical: Some(HistoricalQueryOptions {
                snapshot: parsed.snapshot,
                valid_at: parsed.valid_at,
            }),
        })
    }

    fn access_profile(&self) -> Option<&String> {
        self.parsed.access_profile.as_ref()
    }

    fn select_clause(&self) -> Option<&strict_query::SelectClause> {
        match &self.parsed.mode {
            strict_query::ParsedReadQueryMode::Query(options) => options.select.as_ref(),
            strict_query::ParsedReadQueryMode::SkipToken { .. } => None,
        }
    }

    fn query_options(&self) -> Option<&strict_query::ReadQueryOptions> {
        match &self.parsed.mode {
            strict_query::ParsedReadQueryMode::Query(options) => Some(options),
            strict_query::ParsedReadQueryMode::SkipToken { .. } => None,
        }
    }

    fn skiptoken(&self) -> Option<&str> {
        match &self.parsed.mode {
            strict_query::ParsedReadQueryMode::SkipToken { token } => Some(token),
            strict_query::ParsedReadQueryMode::Query(_) => None,
        }
    }

    fn has_non_projection_query_members(&self) -> bool {
        self.request_history_after_proposal_version.is_some()
            || self.has_non_history_query_members()
    }

    fn has_non_history_query_members(&self) -> bool {
        self.parsed.as_of.is_some()
            || self.skiptoken().is_some()
            || self.query_options().is_some_and(|options| {
                options.filter.is_some()
                    || options.orderby.is_some()
                    || options.top.is_some()
                    || options.count.is_some()
                    || options.bbox.is_some()
            })
    }

    fn has_any_query_member(&self) -> bool {
        self.request_history_after_proposal_version.is_some()
            || self.parsed.as_of.is_some()
            || self.skiptoken().is_some()
            || self.query_options().is_some_and(|options| {
                options.select.is_some()
                    || options.filter.is_some()
                    || options.orderby.is_some()
                    || options.top.is_some()
                    || options.count.is_some()
                    || options.bbox.is_some()
            })
    }
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            request_history_after_proposal_version: None,
            parsed: strict_query::ParsedReadQuery {
                access_profile: None,
                as_of: None,
                mode: strict_query::ParsedReadQueryMode::Query(
                    strict_query::ReadQueryOptions::default(),
                ),
            },
            historical: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryParseError {
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadQueryError {
    Invalid,
    CursorInvalid,
}

fn percent_decode(value: &str) -> Result<String, QueryParseError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = hex(bytes[index + 1]).ok_or(QueryParseError::Invalid)?;
                let low = hex(bytes[index + 2]).ok_or(QueryParseError::Invalid)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return Err(QueryParseError::Invalid),
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| QueryParseError::Invalid)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Invoke => "invoke",
        Operation::Get => "get",
        Operation::List => "list",
        Operation::Lookup => "lookup",
        Operation::Create => "create",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
        Operation::SubmitRequest => "submit_request",
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
        Operation::Snapshot => "snapshot",
    }
}

fn valid_canonical_record_uuid(value: &str) -> bool {
    value.len() == 36
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

fn canonical_revision(value: &str) -> Option<i64> {
    let revision = value.parse::<i64>().ok()?;
    (revision > 0 && revision.to_string() == value).then_some(revision)
}

fn method_name(method: crate::model::HttpMethod) -> &'static str {
    match method {
        crate::model::HttpMethod::Delete => "delete",
        crate::model::HttpMethod::Get => "get",
        crate::model::HttpMethod::Patch => "patch",
        crate::model::HttpMethod::Post => "post",
    }
}

/// Mark a refusal of a request that carries no principal, so the telemetry
/// boundary counts it instead of the journal recording it.
///
/// A caller with no principal names nobody the journal could hold
/// accountable, and an unauthenticated caller that could append would grow
/// the hash chain without bound and serialize every audited write behind its
/// head lock. The refusal keeps its operational signal as a bounded counter
/// and a debug line; refusals of an authenticated principal are unaffected
/// and still append.
fn anonymous_refusal(mut response: Response, reason: AnonymousRefusalReason) -> Response {
    tracing::debug!(
        reason = reason.label(),
        "refused a request without a principal before admission"
    );
    response
        .extensions_mut()
        .insert(AnonymousRefusal { reason });
    response
}

fn concealed() -> Response {
    fixed_problem(
        StatusCode::NOT_FOUND,
        "resource.not_found",
        "The requested resource was not found.",
    )
}

fn unavailable() -> Response {
    fixed_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
        "The Registry data service is unavailable.",
    )
}

fn invalid_query() -> Response {
    fixed_problem(
        StatusCode::BAD_REQUEST,
        "query.invalid",
        "The query request is invalid.",
    )
}

fn cursor_invalid() -> Response {
    fixed_problem(
        StatusCode::BAD_REQUEST,
        "query.cursor_invalid",
        "The query cursor is invalid.",
    )
}

fn lookup_unresolved() -> Response {
    fixed_problem(
        StatusCode::NOT_FOUND,
        "lookup.unresolved",
        "The lookup did not resolve exactly one record.",
    )
}

fn exact_read(response: HeldReadResponse, entity: &CompiledEntity) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, response.content_type())
        .header(CACHE_CONTROL, "no-store")
        .header(VARY, "authorization, accept");
    if matches!(
        response.content_type(),
        "application/json" | "application/ld+json"
    ) {
        let Ok(link) = record_profile::link_header_value(entity) else {
            return unavailable();
        };
        builder = builder.header(LINK, link);
    }
    if let Some(etag) = response.strong_etag() {
        let Ok(etag) = HeaderValue::from_bytes(etag) else {
            return unavailable();
        };
        builder = builder.header(ETAG, etag);
    }
    builder
        .body(Body::from(response.body().to_vec()))
        .unwrap_or_else(|_| unavailable())
}

fn exact_read_no_store(response: HeldReadResponse, entity: &CompiledEntity) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, response.content_type())
        .header(CACHE_CONTROL, "no-store")
        .header(VARY, "authorization, accept");
    if matches!(
        response.content_type(),
        "application/json" | "application/ld+json"
    ) {
        let Ok(link) = record_profile::link_header_value(entity) else {
            return unavailable();
        };
        builder = builder.header(LINK, link);
    }
    builder
        .body(Body::from(response.body().to_vec()))
        .unwrap_or_else(|_| unavailable())
}

fn exact_non_record_no_store(response: HeldReadResponse) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, response.content_type())
        .header(CACHE_CONTROL, "no-store")
        .header(VARY, "authorization, accept")
        .body(Body::from(response.body().to_vec()))
        .unwrap_or_else(|_| unavailable())
}

fn negotiated_read_representation(headers: &HeaderMap) -> CursorRepresentation {
    let mut json_quality: Option<(u16, u8)> = None;
    let mut json_ld_quality: Option<(u16, u8)> = None;
    let mut geojson_quality: Option<(u16, u8)> = None;
    for value in headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        for media_range in value.split(',') {
            let mut parts = media_range.split(';');
            let media = parts.next().unwrap_or_default().trim();
            let quality = accept_quality(parts);
            if quality == 0 {
                continue;
            }
            if media.eq_ignore_ascii_case("application/geo+json") {
                geojson_quality = Some(geojson_quality.unwrap_or_default().max((quality, 3)));
            } else if media.eq_ignore_ascii_case("application/ld+json") {
                json_ld_quality = Some(json_ld_quality.unwrap_or_default().max((quality, 3)));
            } else if media.eq_ignore_ascii_case("application/json") {
                json_quality = Some(json_quality.unwrap_or_default().max((quality, 3)));
            } else if media == "*/*" || media.eq_ignore_ascii_case("application/*") {
                json_quality = Some(json_quality.unwrap_or_default().max((quality, 1)));
            }
        }
    }
    let json = json_quality.unwrap_or_default();
    let json_ld = json_ld_quality.unwrap_or_default();
    let geojson = geojson_quality.unwrap_or_default();
    if geojson_quality.is_some() && geojson > json && geojson > json_ld {
        CursorRepresentation::GeoJson
    } else if json_ld_quality.is_some() && json_ld > json {
        CursorRepresentation::JsonLd
    } else {
        CursorRepresentation::Json
    }
}

fn negotiated_json_representation(headers: &HeaderMap) -> CursorRepresentation {
    match negotiated_read_representation(headers) {
        CursorRepresentation::JsonLd => CursorRepresentation::JsonLd,
        CursorRepresentation::Json | CursorRepresentation::GeoJson => CursorRepresentation::Json,
    }
}

fn negotiated_record_representation(headers: &HeaderMap) -> RecordRepresentation {
    match negotiated_json_representation(headers) {
        CursorRepresentation::JsonLd => RecordRepresentation::JsonLd,
        CursorRepresentation::Json | CursorRepresentation::GeoJson => RecordRepresentation::Json,
    }
}

fn accept_quality<'a>(parameters: impl Iterator<Item = &'a str>) -> u16 {
    for parameter in parameters {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        return parse_accept_quality(value.trim()).unwrap_or(0);
    }
    1000
}

fn parse_accept_quality(value: &str) -> Option<u16> {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let base = match whole {
        "0" => 0,
        "1" if fraction.chars().all(|character| character == '0') => 1000,
        _ => return None,
    };
    if base == 1000 {
        return Some(base);
    }
    if fraction.len() > 3 || !fraction.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    let mut scaled = 0u16;
    let mut factor = 100u16;
    for digit in fraction.bytes() {
        scaled += u16::from(digit - b'0') * factor;
        factor /= 10;
    }
    Some(scaled)
}

fn geojson_available(surface: &AuthorizedSurface<'_>) -> bool {
    if surface.read_path.is_some() {
        return false;
    }
    let Some(geojson) = surface.response_entity.geojson.as_ref() else {
        return false;
    };
    surface.readable_fields.contains(&geojson.geometry_field)
        && matches!(
            data_field_type(surface.response_entity, &geojson.geometry_field),
            Some(FieldTypeSource::Crs84Point { .. })
        )
}

fn exact_mutation(response: &HeldResponse) -> Response {
    let mut builder = Response::builder()
        .status(response.status())
        .header(CACHE_CONTROL, "no-store")
        .header(VARY, "authorization, accept");
    for (name, value) in response.headers() {
        let Ok(value) = HeaderValue::from_bytes(value) else {
            return unavailable();
        };
        builder = match name {
            PermittedResponseHeader::ContentType => builder.header(CONTENT_TYPE, value),
            PermittedResponseHeader::Etag => builder.header("etag", value),
            PermittedResponseHeader::Link => builder.header(LINK, value),
            PermittedResponseHeader::Location => builder.header("location", value),
        };
    }
    builder
        .body(Body::from(response.body().to_vec()))
        .unwrap_or_else(|_| unavailable())
}

async fn bounded_body(body: Body) -> Result<Vec<u8>, ()> {
    bounded_body_to(body, MAX_MUTATION_BODY_BYTES).await
}

async fn bounded_body_to(body: Body, maximum_bytes: usize) -> Result<Vec<u8>, ()> {
    let bytes = to_bytes(body, maximum_bytes).await.map_err(|_| ())?;
    if bytes.is_empty() {
        return Err(());
    }
    Ok(bytes.to_vec())
}

struct ParsedBatchBody {
    items: Vec<BatchMutationItem>,
    change_context: Option<crate::history_context::ChangeContext>,
}

fn parse_batch_body(body: &[u8], maximum_items: usize) -> Result<ParsedBatchBody, ()> {
    let value = parse_json_strict(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "items" | "changeContext"))
    {
        return Err(());
    }
    let change_context = object
        .get("changeContext")
        .map(crate::history_context::ChangeContext::parse_json)
        .transpose()
        .map_err(|_| ())?;
    let items = object.get("items").and_then(Value::as_array).ok_or(())?;
    if items.is_empty() || items.len() > maximum_items {
        return Err(());
    }
    let items = items
        .iter()
        .map(|item| {
            let object = item.as_object().ok_or(())?;
            match object.get("operation").and_then(Value::as_str) {
                Some("create")
                    if object.len() == 2 && object.get("data").is_some_and(Value::is_object) =>
                {
                    Ok(BatchMutationItem::Create(
                        object["data"].as_object().expect("checked object").clone(),
                    ))
                }
                Some("patch")
                    if object.len() == 4
                        && object.contains_key("recordId")
                        && object.contains_key("ifMatch")
                        && object.contains_key("patch") =>
                {
                    let record_id = object["recordId"].as_str().ok_or(())?;
                    let expected_etag = object["ifMatch"].as_str().ok_or(())?;
                    if !Uuid::parse_str(record_id)
                        .is_ok_and(|identifier| identifier.to_string() == record_id)
                        || !valid_if_match(expected_etag)
                    {
                        return Err(());
                    }
                    let patch =
                        parse_json_patch_document(object["patch"].clone()).map_err(|_| ())?;
                    Ok(BatchMutationItem::Patch {
                        record_id: record_id.to_owned(),
                        expected_etag: expected_etag.to_owned(),
                        patch,
                    })
                }
                _ => Err(()),
            }
        })
        .collect::<Result<Vec<_>, ()>>()?;
    Ok(ParsedBatchBody {
        items,
        change_context,
    })
}

async fn body_is_empty(body: Body) -> bool {
    to_bytes(body, 0).await.is_ok_and(|bytes| bytes.is_empty())
}

fn parse_create_body(body: &[u8]) -> Result<Map<String, Value>, ()> {
    let value = parse_json_strict(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object.len() != 1 {
        return Err(());
    }
    object
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(())
}

fn parse_request_action_body(
    operation: Operation,
    request_stage: Option<&str>,
    body: &[u8],
) -> Result<RequestActionBody, ()> {
    let value = parse_json_strict(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    match operation {
        Operation::SubmitRequest if request_stage.is_none() => {
            parse_empty_action_object(object)?;
            Ok(RequestActionBody::Submit)
        }
        Operation::ApproveRequest if request_stage.is_some() => {
            let (proposal_version, effect_digest) = parse_bound_proposal_action(object)?;
            Ok(RequestActionBody::Approve {
                proposal_version,
                effect_digest,
            })
        }
        Operation::RejectRequest if request_stage.is_some() => {
            let (proposal_version, effect_digest) = parse_bound_proposal_action(object)?;
            Ok(RequestActionBody::Reject {
                proposal_version,
                effect_digest,
            })
        }
        Operation::RequestRevision if request_stage.is_some() => {
            let (proposal_version, effect_digest) = parse_bound_proposal_action(object)?;
            Ok(RequestActionBody::RequestRevision {
                proposal_version,
                effect_digest,
            })
        }
        Operation::ReviseRequest if request_stage.is_none() => {
            if object.len() != 1 {
                return Err(());
            }
            let rebase = object.get("rebase").and_then(Value::as_bool).ok_or(())?;
            Ok(RequestActionBody::Revise { rebase })
        }
        Operation::CancelRequest if request_stage.is_none() => {
            parse_empty_action_object(object)?;
            Ok(RequestActionBody::Cancel)
        }
        Operation::ApplyRequest if request_stage.is_none() => {
            let (proposal_version, effect_digest) = parse_bound_proposal_action(object)?;
            Ok(RequestActionBody::Apply {
                proposal_version,
                effect_digest,
            })
        }
        _ => Err(()),
    }
}

fn parse_empty_action_object(object: &Map<String, Value>) -> Result<(), ()> {
    if object.is_empty() {
        Ok(())
    } else {
        Err(())
    }
}

fn parse_bound_proposal_action(object: &Map<String, Value>) -> Result<(u32, String), ()> {
    if object.len() != 2 {
        return Err(());
    }
    let version = object
        .get("proposalVersion")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(())?;
    let digest = object
        .get("effectDigest")
        .and_then(Value::as_str)
        .filter(|value| valid_sha256_digest(value))
        .ok_or(())?;
    Ok((version, digest.to_owned()))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn single_content_type(headers: &HeaderMap, expected: &str) -> bool {
    single_header(headers, CONTENT_TYPE.as_str()) == Some(expected)
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDEMPOTENCY_KEY_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x7e) && byte != b',' && byte != b';')
}

fn valid_if_match(value: &str) -> bool {
    value.len() > 7
        && value.len() <= 256
        && value.starts_with("\"breg-")
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn invalid_request() -> Response {
    fixed_problem(
        StatusCode::BAD_REQUEST,
        "request.invalid",
        "The request is invalid.",
    )
}

fn unsupported_media_type() -> Response {
    fixed_problem(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported.media_type",
        "The request media type is not supported.",
    )
}

fn precondition_required() -> Response {
    fixed_problem(
        StatusCode::PRECONDITION_REQUIRED,
        "precondition.required",
        "The mutation precondition is required.",
    )
}

fn precondition_failed() -> Response {
    fixed_problem(
        StatusCode::PRECONDITION_FAILED,
        "precondition.failed",
        "The mutation precondition failed.",
    )
}

fn mutation_problem(error: MutationError) -> Response {
    match error {
        MutationError::InvalidRequest => invalid_request(),
        MutationError::PreconditionFailed => precondition_failed(),
        MutationError::Conflict => fixed_problem(
            StatusCode::CONFLICT,
            "mutation.conflict",
            "The mutation conflicts with current state.",
        ),
        MutationError::IdempotencyConflict => fixed_problem(
            StatusCode::CONFLICT,
            "idempotency.conflict",
            "The idempotency key is bound to another request.",
        ),
        MutationError::Unavailable | MutationError::RetryableConflict => fixed_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "service.unavailable",
            "The Registry mutation service is unavailable.",
        ),
        MutationError::PlannerFailure(error) => {
            let (status, code, detail) = planner_failure_problem(error);
            fixed_problem(status, code, detail)
        }
    }
}

/// The status, problem code, and detail for one bounded planner failure.
///
/// The detail is the planner's own, so it names the failure kind from the
/// closed vocabulary and nothing else. A planner that ran out of time is a
/// service outage rather than a refusal, so it keeps the unavailable mapping
/// every other timeout carries.
const fn planner_failure_problem(
    error: crate::rhai_planner::ChangeRequestPlannerError,
) -> (StatusCode, &'static str, &'static str) {
    use crate::rhai_planner::ChangeRequestPlannerError as Kind;

    match error {
        Kind::Deadline => (
            StatusCode::SERVICE_UNAVAILABLE,
            "service.unavailable",
            error.problem_detail(),
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "request.plan_refused",
            error.problem_detail(),
        ),
    }
}

fn fixed_problem(status: StatusCode, code: &'static str, detail: &'static str) -> Response {
    crate::correlation::problem_response(
        status,
        format!("urn:breg:problem:{code}"),
        status.canonical_reason().unwrap_or("Request failed"),
        detail,
        code,
    )
}

#[cfg(test)]
mod batch_admission_tests {
    use super::parse_batch_body;
    use serde_json::json;

    #[test]
    fn correction_context_is_shared_and_validated_before_items_execute() {
        let item = json!({"operation": "create", "data": {"label": "fixture"}});
        let accepted = json!({
            "items": [item.clone()],
            "changeContext": {"kind": "correction", "reasonCode": "verified-source"}
        });
        let parsed = parse_batch_body(&serde_json::to_vec(&accepted).unwrap(), 1).unwrap();
        assert_eq!(parsed.items.len(), 1);
        assert!(parsed.change_context.is_some());
        for refused in [
            json!({"items": [item.clone()], "changeContext": null}),
            json!({"items": [item.clone()], "changeContext": {"kind": "correction"}}),
            json!({"items": [item.clone()], "changeContext": {"reasonCode": "x".repeat(65)}}),
            json!({"items": [item.clone()], "changeContext": {"actor": "untrusted"}}),
            json!({"items": [item.clone()], "reasonCode": "unscoped"}),
            json!({"items": [{"operation": "create", "data": {}, "changeContext": {}}]}),
            json!({"items": [item.clone(), item], "changeContext": {}}),
        ] {
            assert!(parse_batch_body(&serde_json::to_vec(&refused).unwrap(), 1).is_err());
        }
        assert!(parse_batch_body(br#"{"items":[],"items":[]}"#, 1).is_err());
    }
}

#[cfg(test)]
mod planner_failure_problem_tests {
    use super::planner_failure_problem;
    use crate::rhai_planner::ChangeRequestPlannerError;
    use axum::http::StatusCode;

    #[test]
    fn every_planner_refusal_names_its_kind_and_nothing_else() {
        for error in ChangeRequestPlannerError::PLAN_REFUSALS {
            let (status, code, detail) = planner_failure_problem(error);
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(code, "request.plan_refused");
            assert!(
                detail.ends_with(&format!("{}.", error.code())),
                "the detail must end with the closed planner vocabulary: {detail}"
            );
        }
    }

    #[test]
    fn a_planner_deadline_stays_the_unavailable_refusal() {
        let (status, code, _) = planner_failure_problem(ChangeRequestPlannerError::Deadline);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "service.unavailable");
    }
}

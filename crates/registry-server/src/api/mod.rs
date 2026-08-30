// SPDX-License-Identifier: Apache-2.0
//! HTTP surface compiled from one immutable Registry inventory.

mod context;
mod service;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{middleware, Extension, Json, Router};
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httpsec::{security_headers, CspBuilder, Problem};
use serde_json::{json, Map, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub use context::{
    AuthorizedRequestContext, RowBoundaryOperator, VerifiedClaimValue, VerifiedContextError,
    VerifiedRequestClaims, VerifiedRowBoundary,
};
pub use service::{
    BatchMutationInput, CompiledReadQuery, ConditionalMutationInput, HeldReadResponse, HttpService,
    ReadFilterClause, ReadRuntimeIdentity, ReadServiceError, ReadinessProbe, RecordReadRefusal,
    RecordReadRequest, RecordReadService, RevisionReadRefusal, RevisionReadRequest,
    RevisionReadService, ServiceFuture,
};

use crate::auth::{authenticate_request, RegistryAuthenticator};
use crate::contract::{AccessProfileSource, BoundaryOperator, Classification, Operation};
use crate::cursor::{now_unix_seconds, CursorBinding, CursorError};
use crate::idempotency::{HeldResponse, PermittedResponseHeader};
use crate::model::{
    CompiledEntity, CompiledMetadataEntity, CompiledMetadataEntry, CompiledQueryFilterOperator,
    CompiledQueryKind, CompiledQueryOperation, CompiledRevisionKind, CompiledRoute,
    MAX_REVISION_HISTORY_RECORDS,
};
use crate::mutation::{parse_json_patch_document, BatchMutationItem, MutationError};
use uuid::Uuid;

const MAX_FIELDS: usize = 128;
const MAX_FIELD_BYTES: usize = 128;
const MAX_MUTATION_BODY_BYTES: usize = 2 * 1024 * 1024;
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
    route_set(service).layer(security_headers(CspBuilder::restrictive()))
}

fn route_set(service: Arc<HttpService>) -> Router {
    let mut app = Router::new()
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
            Operation::Revisions if service.revisions.is_some() => app.route(
                &route.path,
                get(revision_dispatch).layer(Extension(route.clone())),
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
            _ => app,
        };
    }

    app.fallback(not_found)
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
    if options.access_profile.is_some() && visible.is_empty() {
        return concealed();
    }

    let mut paths = Map::new();
    let mut readable_by_entity: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for surface in &visible {
        let path = paths
            .entry(surface.route.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(methods) = path else {
            unreachable!("OpenAPI paths are objects")
        };
        let mut operation = Map::from_iter([
            ("operationId".to_owned(), json!(surface.route.id)),
            (
                "x-registry-entity".to_owned(),
                json!(surface.route.entity_id),
            ),
            (
                "x-registry-operation".to_owned(),
                json!(operation_name(surface.route.operation)),
            ),
            (
                "x-registry-accessProfile".to_owned(),
                json!(surface.context.selected_profile()),
            ),
            (
                "responses".to_owned(),
                json!({"200": {"description": "Operation completed"}}),
            ),
        ]);
        if let Some(kind) = surface.route.query_kind {
            operation.insert(
                "x-registry-queryKind".to_owned(),
                Value::String(query_kind_name(kind).to_owned()),
            );
            operation.insert("parameters".to_owned(), query_parameters(kind));
        } else if let Some(kind) = surface.route.revision_kind {
            operation.insert("parameters".to_owned(), revision_parameters(kind));
            operation.insert(
                "x-registry-maximumRecords".to_owned(),
                json!(surface.route.maximum_records),
            );
        } else if surface.route.operation == Operation::Batch {
            let batch = surface
                .entity
                .batch
                .as_ref()
                .expect("authorized batch routes have compiled bounds");
            let profile = &surface.entity.access_profiles[surface.context.selected_profile()];
            let allow_create = profile.operations.contains(&Operation::Create);
            let allow_patch = profile.operations.contains(&Operation::Patch);
            operation.insert("parameters".to_owned(), access_profile_parameters());
            operation.insert(
                "x-registry-maximumItems".to_owned(),
                json!(batch.maximum_items),
            );
            operation.insert(
                "x-registry-maximumBytes".to_owned(),
                json!(batch.maximum_bytes),
            );
            operation.insert(
                "requestBody".to_owned(),
                batch_request_body(
                    &surface.route.entity_id,
                    batch.maximum_items,
                    allow_create,
                    allow_patch,
                ),
            );
            operation.insert(
                "responses".to_owned(),
                batch_response(
                    &surface.route.entity_id,
                    batch.maximum_items,
                    allow_create,
                    allow_patch,
                ),
            );
        }
        methods.insert(
            method_name(surface.route.method).to_owned(),
            Value::Object(operation),
        );
        readable_by_entity
            .entry(surface.route.entity_id.clone())
            .and_modify(|fields| {
                *fields = fields
                    .intersection(&surface.readable_fields)
                    .cloned()
                    .collect();
            })
            .or_insert_with(|| surface.readable_fields.clone());
    }

    let schemas = readable_by_entity
        .iter()
        .filter_map(|(entity_id, readable)| {
            filtered_schema(&service, entity_id, readable).map(|schema| (entity_id.clone(), schema))
        })
        .collect::<Map<String, Value>>();
    Json(json!({
        "openapi": "3.1.0",
        "info": {"title": service.registry.registry_id(), "version": service.registry.version()},
        "paths": paths,
        "components": {"schemas": schemas}
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
    let visible = visible_metadata_entries(&service, &claims, &options);
    if options.access_profile.is_some() && visible.is_empty() {
        return concealed();
    }

    let mut entities: BTreeMap<String, MetadataEntity> = BTreeMap::new();
    for (metadata_entity, entry) in visible {
        entities
            .entry(metadata_entity.id.clone())
            .and_modify(|metadata| {
                metadata
                    .operations
                    .insert(entry.operation, entry.access_profile.clone());
                metadata.readable_fields = metadata
                    .readable_fields
                    .intersection(&entry.readable_fields)
                    .cloned()
                    .collect();
            })
            .or_insert_with(|| MetadataEntity {
                id: metadata_entity.id.clone(),
                route: metadata_entity.route.clone(),
                operations: BTreeMap::from([(entry.operation, entry.access_profile.clone())]),
                readable_fields: entry.readable_fields.clone(),
                schema_path: metadata_entity.schema_path.clone(),
            });
    }
    let entities = entities
        .into_values()
        .map(|entity| {
            json!({
                "id": entity.id,
                "route": entity.route,
                "operations": entity.operations.into_iter().map(|(operation, access_profile)| json!({
                    "operation": operation_name(operation),
                    "accessProfile": access_profile,
                })).collect::<Vec<_>>(),
                "readableFields": entity.readable_fields,
                "schema": entity.schema_path,
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "id": service.registry.registry_id(),
        "version": service.registry.version(),
        "revision": service.registry.revision(),
        "entities": entities,
    }))
    .into_response()
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
        .filter(|surface| surface.route.entity_id == entity_id)
        .collect::<Vec<_>>();
    let Some(first) = surfaces.first() else {
        return concealed();
    };
    let readable =
        surfaces
            .iter()
            .skip(1)
            .fold(first.readable_fields.clone(), |fields, surface| {
                fields
                    .intersection(&surface.readable_fields)
                    .cloned()
                    .collect()
            });
    match filtered_schema(&service, &entity_id, &readable) {
        Some(schema) => Json(schema).into_response(),
        None => concealed(),
    }
}

async fn read_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
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
            )
            .await;
        }
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        let response =
            audited_read_concealment(&service, &route, &options, &claims, path.get("record_id"))
                .await;
        return response;
    };
    let query = if route.operation == Operation::List {
        match read_query(&service, &route, &surface, &options).await {
            Ok(query) => query,
            Err(ReadQueryError::Invalid) => {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    path.get("record_id"),
                    invalid_query(),
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
                )
                .await;
            }
        }
    } else {
        if options.has_list_query_members() {
            return audited_read_refusal(
                &service,
                &route,
                &surface,
                path.get("record_id"),
                invalid_query(),
            )
            .await;
        }
        None
    };
    let readable_fields = if let Some(query) = &query {
        query
            .cursor_binding
            .selected_fields
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    } else {
        match &options.fields {
            Some(fields) if fields.is_subset(&surface.readable_fields) => fields.clone(),
            Some(_) => {
                return audited_read_refusal(
                    &service,
                    &route,
                    &surface,
                    path.get("record_id"),
                    concealed(),
                )
                .await;
            }
            None => surface.readable_fields.clone(),
        }
    };
    if !readable_fields.is_subset(&surface.readable_fields) {
        return audited_read_refusal(
            &service,
            &route,
            &surface,
            path.get("record_id"),
            concealed(),
        )
        .await;
    }
    let request = RecordReadRequest {
        entity_id: route.entity_id.clone(),
        operation_id: route.id.clone(),
        method: route.method,
        record_id: path.get("record_id").cloned(),
        context: surface.context,
        selected_fields: readable_fields.clone(),
        maximum_records: query
            .as_ref()
            .map_or(1, |query| usize::from(query.page_size) + 1),
        query,
    };

    match route.operation {
        Operation::Get => match service.records.get(request).await {
            Ok(Some(record)) => exact_json(record),
            Ok(None) => concealed(),
            Err(ReadServiceError::Unavailable) => unavailable(),
            Err(ReadServiceError::CursorInvalid) => cursor_invalid(),
        },
        Operation::List => match service.records.list(request).await {
            Ok(response) => exact_json_no_store(response),
            Err(ReadServiceError::Unavailable) => unavailable(),
            Err(ReadServiceError::CursorInvalid) => cursor_invalid(),
        },
        _ => concealed(),
    }
}

async fn revision_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
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
        )
        .await;
    };
    let Some(record_id) = path.get("record_id") else {
        return audited_revision_refusal(revisions.as_ref(), &route, &surface, None, concealed())
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
        maximum_records,
    };
    match route.revision_kind {
        Some(CompiledRevisionKind::List) => match revisions.list(request).await {
            Ok(Some(response)) => exact_json_no_store(response),
            Ok(None) => concealed(),
            Err(_) => unavailable(),
        },
        Some(CompiledRevisionKind::Detail) => match revisions.detail(request).await {
            Ok(Some(response)) => exact_json_no_store(response),
            Ok(None) => concealed(),
            Err(_) => unavailable(),
        },
        None => concealed(),
    }
}

async fn audited_known_revision_refusal(
    revisions: &dyn RevisionReadService,
    route: &CompiledRoute,
    claims: &VerifiedRequestClaims,
    target_record: Option<&String>,
    response: Response,
) -> Response {
    match revisions
        .refusal(RevisionReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: claims.principal().map(str::to_owned),
            selected_access_profile: None,
            purpose_present: claims.purpose().is_some(),
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
) -> Response {
    match revisions
        .refusal(RevisionReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: surface.context.principal().map(str::to_owned),
            selected_access_profile: Some(surface.context.selected_profile().to_owned()),
            purpose_present: surface.context.purpose().is_some(),
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
) -> Response {
    let selected_access_profile = options.access_profile.as_ref().and_then(|profile| {
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
) -> Response {
    match service
        .records
        .refusal(RecordReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: claims.principal().map(str::to_owned),
            selected_access_profile: None,
            purpose_present: claims.purpose().is_some(),
        })
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
) -> Response {
    match service
        .records
        .refusal(RecordReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: surface.context.principal().map(str::to_owned),
            selected_access_profile: Some(surface.context.selected_profile().to_owned()),
            purpose_present: surface.context.purpose().is_some(),
        })
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
) -> Response {
    let selected_access_profile = options.access_profile.as_ref().and_then(|profile| {
        route
            .access_profiles
            .iter()
            .any(|candidate| candidate == profile)
            .then_some(profile.clone())
    });
    match service
        .records
        .refusal(RecordReadRefusal {
            method: route.method,
            operation_id: route.id.clone(),
            target_record: target_record.cloned(),
            principal: claims.principal().map(str::to_owned),
            selected_access_profile,
            purpose_present: claims.purpose().is_some(),
        })
        .await
    {
        Ok(()) => concealed(),
        Err(_) => unavailable(),
    }
}

async fn create_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
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
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_mutation_concealment(mutations, &route, &options, &claims, None).await;
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key") else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
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
        )
        .await;
    };
    match mutations
        .create(
            &route.id,
            idempotency_key,
            &surface.context,
            &route.entity_id,
            data,
            surface.readable_fields,
        )
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

async fn patch_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
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
        )
        .await;
    };
    let Some(surface) = authorize_route(&service, &route, &claims, &options) else {
        return audited_mutation_concealment(mutations, &route, &options, &claims, None).await;
    };
    let Some(batch) = surface.entity.batch.as_ref() else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
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
        )
        .await;
    };
    let Ok(items) = parse_batch_body(&body, usize::from(batch.maximum_items)) else {
        return audited_mutation_refusal(
            mutations,
            &route,
            &surface.context,
            None,
            invalid_request(),
        )
        .await;
    };
    match mutations
        .batch(BatchMutationInput {
            route_id: &route.id,
            idempotency_key,
            context: &surface.context,
            entity_id: &route.entity_id,
            items,
            response_fields: surface.readable_fields,
            body_bytes: body.len(),
        })
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

async fn tombstone_dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledRoute>,
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
        })
        .await
    {
        Ok(outcome) => exact_mutation(outcome.response()),
        Err(error) => mutation_problem(error),
    }
}

async fn audited_mutation_refusal(
    mutations: &crate::postgres::PostgresRecordMutationService,
    route: &CompiledRoute,
    context: &AuthorizedRequestContext,
    target_record: Option<&str>,
    response: Response,
) -> Response {
    match mutations
        .record_refusal(
            route.method,
            &route.id,
            target_record,
            context.principal(),
            Some(context.selected_profile()),
            context.purpose().is_some(),
        )
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
) -> Response {
    let selected_profile = options
        .access_profile
        .as_deref()
        .or(Some(route.default_access_profile.as_str()));
    match mutations
        .record_refusal(
            route.method,
            &route.id,
            target_record,
            claims.principal(),
            selected_profile,
            claims.purpose().is_some(),
        )
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
    context: AuthorizedRequestContext,
    readable_fields: BTreeSet<String>,
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
    })?;
    Some((entity, entry))
}

fn authorize_route<'a>(
    service: &'a HttpService,
    route: &'a CompiledRoute,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Option<AuthorizedSurface<'a>> {
    let access =
        service.registry.access().entries.iter().find(|entry| {
            entry.entity_id == route.entity_id && entry.operation == route.operation
        })?;
    let selected_profile = options
        .access_profile
        .as_deref()
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
    if matches!(
        route.operation,
        Operation::Create | Operation::Patch | Operation::Tombstone | Operation::Batch
    ) && profile.anonymous
    {
        return None;
    }
    if profile.anonymous {
        if entity.classification != Classification::Public {
            return None;
        }
    } else {
        let expected_claim = profile.principal_claim.as_deref()?;
        if claims.principal_claim() != Some(expected_claim) || claims.principal().is_none() {
            return None;
        }
    }
    if !profile
        .required_scopes
        .iter()
        .all(|scope| claims.has_scope(scope))
    {
        return None;
    }
    if !profile.required_purposes.is_empty()
        && !claims
            .purpose()
            .is_some_and(|purpose| profile.required_purposes.contains(purpose))
    {
        return None;
    }
    let row_boundaries = verified_row_boundaries(profile, claims)?;
    let readable_fields = profile
        .readable_fields
        .iter()
        .filter(|field| {
            !profile.anonymous
                || entity
                    .fields
                    .get(*field)
                    .is_some_and(|field| field.classification == Classification::Public)
        })
        .cloned()
        .collect();
    Some(AuthorizedSurface {
        route,
        entity,
        context: AuthorizedRequestContext::new(
            claims.principal().map(str::to_owned),
            claims.purpose().map(str::to_owned),
            selected_profile.to_owned(),
            row_boundaries,
        ),
        readable_fields,
    })
}

fn served_operation(service: &HttpService, route: &CompiledRoute) -> bool {
    match route.operation {
        Operation::Get | Operation::List => true,
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
    }
}

fn verified_row_boundaries(
    profile: &AccessProfileSource,
    claims: &VerifiedRequestClaims,
) -> Option<Vec<VerifiedRowBoundary>> {
    profile
        .row_boundaries
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
) -> Result<Option<CompiledReadQuery>, ReadQueryError> {
    let Some(kind) = route.query_kind else {
        return Ok(None);
    };
    let Some(operation) = query_operation_for_route(service, route, surface, kind) else {
        return Err(ReadQueryError::Invalid);
    };
    if let Some(token) = &options.cursor {
        let payload = service
            .cursors
            .open_after_authorization(token, now_unix_seconds(), |payload| {
                if payload.binding.route_id != route.id
                    || payload.binding.query_operation_id != operation.id
                    || payload.binding.query_kind != kind
                    || payload.binding.selected_profile != surface.context.selected_profile()
                {
                    return Err(CursorError::Mismatch);
                }
                let fields = payload
                    .binding
                    .selected_fields
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let filters = cursor_filters_to_read_filters(&payload.query.filters)
                    .map_err(|_| CursorError::Mismatch)?;
                validate_query_shape(
                    surface.entity,
                    operation,
                    &filters,
                    payload.query.sort.as_deref(),
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
                        filters: &filters,
                        sort: payload.query.sort.as_deref(),
                        page_size: payload.binding.page_size,
                        temporal_instant: payload.binding.temporal_instant.as_deref(),
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
        let filters = cursor_filters_to_read_filters(&payload.query.filters)?;
        return Ok(Some(CompiledReadQuery {
            route_id: route.id.clone(),
            query_operation_id: operation.id.clone(),
            kind,
            cursor_binding: payload.binding.clone(),
            cursor_query: payload.query.clone(),
            filters,
            sort: payload.query.sort,
            page_size: payload.binding.page_size,
            temporal_instant: payload.binding.temporal_instant,
            continuation: Some(payload.continuation),
        }));
    }

    let fields = match &options.fields {
        Some(fields) if fields.is_subset(&surface.readable_fields) => fields.clone(),
        Some(_) => return Err(ReadQueryError::Invalid),
        None => operation.projection_fields.iter().cloned().collect(),
    };
    if fields.is_empty() || !fields.is_subset(&surface.readable_fields) {
        return Err(ReadQueryError::Invalid);
    }
    let filters = first_page_filters(operation, &options.filters)?;
    let sort = options.sort.clone();
    let page_size = options.page_size.unwrap_or(operation.max_page_size);
    validate_query_shape(
        surface.entity,
        operation,
        &filters,
        sort.as_deref(),
        page_size,
    )?;
    let temporal_instant = temporal_instant_for(kind, options)?;
    let binding = cursor_binding(
        service,
        route,
        surface,
        operation,
        CursorBindingQuery {
            selected_fields: &fields,
            filters: &filters,
            sort: sort.as_deref(),
            page_size,
            temporal_instant: temporal_instant.as_deref(),
        },
    )
    .map_err(|_| ReadQueryError::Invalid)?;
    Ok(Some(CompiledReadQuery {
        route_id: route.id.clone(),
        query_operation_id: operation.id.clone(),
        kind,
        cursor_binding: binding,
        cursor_query: crate::cursor::CursorQuery {
            filters: cursor_filters(&filters),
            sort: sort.clone(),
        },
        filters,
        sort,
        page_size,
        temporal_instant,
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
                && operation.entity_id == route.entity_id
                && operation.profile_id == surface.context.selected_profile()
                && operation.kind == kind
        })
}

fn first_page_filters(
    operation: &CompiledQueryOperation,
    filters: &[RawFilterClause],
) -> Result<Vec<ReadFilterClause>, ReadQueryError> {
    let mut result = Vec::new();
    let mut in_values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut non_in_fields = BTreeSet::new();
    for filter in filters {
        let field = operation
            .filter_fields
            .iter()
            .find(|field| field.field == filter.field)
            .ok_or(ReadQueryError::Invalid)?;
        if !field.operators.contains(&filter.operator) {
            return Err(ReadQueryError::Invalid);
        }
        let values = match filter.operator {
            CompiledQueryFilterOperator::Equals | CompiledQueryFilterOperator::In => {
                vec![filter.value.clone()]
            }
            CompiledQueryFilterOperator::Prefix => vec![filter.value.clone()],
            CompiledQueryFilterOperator::Range => {
                let (lower, upper) = filter
                    .value
                    .split_once("..")
                    .ok_or(ReadQueryError::Invalid)?;
                if lower.is_empty() || upper.is_empty() {
                    return Err(ReadQueryError::Invalid);
                }
                vec![lower.to_owned(), upper.to_owned()]
            }
            CompiledQueryFilterOperator::IsNull | CompiledQueryFilterOperator::IsNotNull => {
                if filter.value != "true" {
                    return Err(ReadQueryError::Invalid);
                }
                vec!["true".to_owned()]
            }
        };
        if filter.operator == CompiledQueryFilterOperator::In {
            if non_in_fields.contains(&filter.field) {
                return Err(ReadQueryError::Invalid);
            }
            in_values
                .entry(filter.field.clone())
                .or_default()
                .insert(values[0].clone());
            continue;
        }
        if in_values.contains_key(&filter.field) {
            return Err(ReadQueryError::Invalid);
        }
        non_in_fields.insert(filter.field.clone());
        result.push(ReadFilterClause {
            field: filter.field.clone(),
            operator: filter.operator,
            values,
        });
    }
    for (field, values) in in_values {
        result.push(ReadFilterClause {
            field,
            operator: CompiledQueryFilterOperator::In,
            values: values.into_iter().collect(),
        });
    }
    result.sort_by(|left, right| (&left.field, left.operator).cmp(&(&right.field, right.operator)));
    Ok(result)
}

fn cursor_filters_to_read_filters(
    filters: &[crate::cursor::CursorFilter],
) -> Result<Vec<ReadFilterClause>, ReadQueryError> {
    filters
        .iter()
        .map(|filter| {
            let operator = match filter.operator.as_str() {
                "equals" => CompiledQueryFilterOperator::Equals,
                "in" => CompiledQueryFilterOperator::In,
                "range" => CompiledQueryFilterOperator::Range,
                "is_null" => CompiledQueryFilterOperator::IsNull,
                "is_not_null" => CompiledQueryFilterOperator::IsNotNull,
                "prefix" => CompiledQueryFilterOperator::Prefix,
                _ => return Err(ReadQueryError::CursorInvalid),
            };
            Ok(ReadFilterClause {
                field: filter.field.clone(),
                operator,
                values: filter.values.clone(),
            })
        })
        .collect()
}

fn validate_query_shape(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    filters: &[ReadFilterClause],
    sort: Option<&str>,
    page_size: u16,
) -> Result<(), ReadQueryError> {
    if page_size == 0 || page_size > operation.max_page_size || filters.len() > MAX_FILTER_CLAUSES {
        return Err(ReadQueryError::Invalid);
    }
    let mut in_values = 0_usize;
    for filter in filters {
        let field = operation
            .filter_fields
            .iter()
            .find(|field| field.field == filter.field)
            .ok_or(ReadQueryError::Invalid)?;
        if !field.operators.contains(&filter.operator) {
            return Err(ReadQueryError::Invalid);
        }
        let compiled_field_type = entity
            .fields
            .get(&filter.field)
            .map(|field| &field.field_type)
            .ok_or(ReadQueryError::Invalid)?;
        match filter.operator {
            CompiledQueryFilterOperator::Equals | CompiledQueryFilterOperator::Prefix => {
                if filter.values.len() != 1 {
                    return Err(ReadQueryError::Invalid);
                }
                crate::postgres::validate_field_value(&filter.values[0], compiled_field_type)
                    .map_err(|_| ReadQueryError::Invalid)?;
            }
            CompiledQueryFilterOperator::In => {
                if filter.values.is_empty() {
                    return Err(ReadQueryError::Invalid);
                }
                in_values += filter.values.len();
                if in_values > MAX_IN_VALUES {
                    return Err(ReadQueryError::Invalid);
                }
                let unique = filter.values.iter().collect::<BTreeSet<_>>();
                if unique.len() != filter.values.len() {
                    return Err(ReadQueryError::Invalid);
                }
                for value in &filter.values {
                    crate::postgres::validate_field_value(value, compiled_field_type)
                        .map_err(|_| ReadQueryError::Invalid)?;
                }
            }
            CompiledQueryFilterOperator::Range => {
                if filter.values.len() != 2 {
                    return Err(ReadQueryError::Invalid);
                }
                for value in &filter.values {
                    crate::postgres::validate_field_value(value, compiled_field_type)
                        .map_err(|_| ReadQueryError::Invalid)?;
                }
            }
            CompiledQueryFilterOperator::IsNull | CompiledQueryFilterOperator::IsNotNull => {
                if filter.values.as_slice() != ["true"] {
                    return Err(ReadQueryError::Invalid);
                }
            }
        }
    }
    if let Some(sort) = sort {
        let sortable = operation
            .sort_fields
            .iter()
            .any(|field| field.field == sort && field.directions.len() == 1);
        if !sortable {
            return Err(ReadQueryError::Invalid);
        }
    }
    Ok(())
}

fn temporal_instant_for(
    kind: CompiledQueryKind,
    options: &QueryOptions,
) -> Result<Option<String>, ReadQueryError> {
    match kind {
        CompiledQueryKind::List => {
            if options.as_of.is_some() {
                return Err(ReadQueryError::Invalid);
            }
            Ok(None)
        }
        CompiledQueryKind::Current => {
            if options.as_of.is_some() {
                return Err(ReadQueryError::Invalid);
            }
            OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map(Some)
                .map_err(|_| ReadQueryError::Invalid)
        }
        CompiledQueryKind::AsOf => {
            let value = options.as_of.as_deref().ok_or(ReadQueryError::Invalid)?;
            parse_strict_rfc3339_utc(value).map_err(|_| ReadQueryError::Invalid)?;
            Ok(Some(value.to_owned()))
        }
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
    let principal_reference = surface
        .context
        .principal()
        .map(|principal| {
            service
                .cursors
                .binding_digest_bytes(b"registry-server-cursor-principal-v1", principal.as_bytes())
        })
        .transpose()?;
    let purpose_reference = surface
        .context
        .purpose()
        .map(|purpose| {
            service
                .cursors
                .binding_digest_bytes(b"registry-server-cursor-purpose-v1", purpose.as_bytes())
        })
        .transpose()?;
    let row_boundary_reference = service.cursors.binding_digest(
        b"registry-server-cursor-row-boundary-v1",
        &json!(surface
            .context
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
    let projection_reference = service.cursors.binding_digest(
        b"registry-server-cursor-projection-v1",
        &json!({"selectedFields": selected_fields_vec}),
    )?;
    let cursor_filters = cursor_filters(query.filters);
    let query_reference = service.cursors.binding_digest(
        b"registry-server-cursor-query-v1",
        &json!({"filters": cursor_filters, "temporalInstant": query.temporal_instant}),
    )?;
    let sort_reference = service.cursors.binding_digest(
        b"registry-server-cursor-sort-v1",
        &json!({"sort": query.sort, "tieBreaker": operation.stable_tie_breaker}),
    )?;
    Ok(CursorBinding {
        package_revision: service.identity.package_revision.clone(),
        schema_fingerprint: service.identity.schema_fingerprint.clone(),
        registry_revision: service.registry.revision().to_owned(),
        route_id: route.id.clone(),
        query_operation_id: operation.id.clone(),
        query_kind: operation.kind,
        selected_profile: surface.context.selected_profile().to_owned(),
        principal_reference,
        purpose_reference,
        row_boundary_reference,
        projection_reference,
        query_reference,
        sort_reference,
        page_size: query.page_size,
        temporal_instant: query.temporal_instant.map(str::to_owned),
        selected_fields: selected_fields_vec,
    })
}

struct CursorBindingQuery<'a> {
    selected_fields: &'a BTreeSet<String>,
    filters: &'a [ReadFilterClause],
    sort: Option<&'a str>,
    page_size: u16,
    temporal_instant: Option<&'a str>,
}

fn cursor_filters(filters: &[ReadFilterClause]) -> Vec<crate::cursor::CursorFilter> {
    filters
        .iter()
        .map(|filter| crate::cursor::CursorFilter {
            field: filter.field.clone(),
            operator: filter_operator_name(filter.operator).to_owned(),
            values: filter.values.clone(),
        })
        .collect()
}

fn filter_operator_name(operator: CompiledQueryFilterOperator) -> &'static str {
    match operator {
        CompiledQueryFilterOperator::Equals => "equals",
        CompiledQueryFilterOperator::In => "in",
        CompiledQueryFilterOperator::Range => "range",
        CompiledQueryFilterOperator::IsNull => "is_null",
        CompiledQueryFilterOperator::IsNotNull => "is_not_null",
        CompiledQueryFilterOperator::Prefix => "prefix",
    }
}

fn filtered_schema(
    service: &HttpService,
    entity_id: &str,
    readable_fields: &BTreeSet<String>,
) -> Option<Value> {
    let path = format!("generated/schemas/{entity_id}.schema.json");
    let artifact = service.registry.artifacts().get(&path)?;
    let mut schema: Value = serde_json::from_slice(&artifact.bytes).ok()?;
    let object = schema.as_object_mut()?;
    let properties = object.get_mut("properties")?.as_object_mut()?;
    properties.retain(|field, _| readable_fields.contains(field));
    if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|field| {
            field
                .as_str()
                .is_some_and(|field| readable_fields.contains(field))
        });
    }
    Some(schema)
}

struct MetadataEntity {
    id: String,
    route: String,
    operations: BTreeMap<Operation, String>,
    readable_fields: BTreeSet<String>,
    schema_path: String,
}

#[derive(Default)]
struct QueryOptions {
    access_profile: Option<String>,
    fields: Option<BTreeSet<String>>,
    filters: Vec<RawFilterClause>,
    sort: Option<String>,
    page_size: Option<u16>,
    as_of: Option<String>,
    cursor: Option<String>,
}

impl QueryOptions {
    fn parse(raw: Option<&str>, allow_fields: bool) -> Result<Self, QueryParseError> {
        let mut result = Self::default();
        let Some(raw) = raw else {
            return Ok(result);
        };
        if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
            return Err(QueryParseError::Invalid);
        }
        let mut in_values = 0_usize;
        for pair in raw.split('&') {
            let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
            let name = percent_decode(name)?;
            let value = percent_decode(value)?;
            match name.as_str() {
                "accessProfile" if result.access_profile.is_none() && valid_id(&value) => {
                    result.access_profile = Some(value);
                }
                "fields" if allow_fields && result.fields.is_none() => {
                    result.fields = Some(parse_fields(&value)?);
                }
                "filter" if allow_fields => {
                    if result.filters.len() >= MAX_FILTER_CLAUSES {
                        return Err(QueryParseError::Invalid);
                    }
                    let filter = parse_raw_filter(&value)?;
                    if filter.operator == CompiledQueryFilterOperator::In {
                        in_values += 1;
                        if in_values > MAX_IN_VALUES {
                            return Err(QueryParseError::Invalid);
                        }
                    }
                    result.filters.push(filter);
                }
                "sort" if allow_fields && result.sort.is_none() && valid_id(&value) => {
                    result.sort = Some(value);
                }
                "pageSize" if allow_fields && result.page_size.is_none() => {
                    let size = value.parse::<u16>().map_err(|_| QueryParseError::Invalid)?;
                    result.page_size = Some(size);
                }
                "asOf" if allow_fields && result.as_of.is_none() => {
                    parse_strict_rfc3339_utc(&value).map_err(|_| QueryParseError::Invalid)?;
                    result.as_of = Some(value);
                }
                "cursor" if allow_fields && result.cursor.is_none() && !value.is_empty() => {
                    result.cursor = Some(value);
                }
                _ => return Err(QueryParseError::Invalid),
            }
        }
        if result.cursor.is_some()
            && (result.fields.is_some()
                || !result.filters.is_empty()
                || result.sort.is_some()
                || result.page_size.is_some()
                || result.as_of.is_some())
        {
            return Err(QueryParseError::Invalid);
        }
        Ok(result)
    }

    fn has_list_query_members(&self) -> bool {
        self.cursor.is_some()
            || !self.filters.is_empty()
            || self.sort.is_some()
            || self.page_size.is_some()
            || self.as_of.is_some()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RawFilterClause {
    field: String,
    operator: CompiledQueryFilterOperator,
    value: String,
}

impl fmt::Debug for RawFilterClause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawFilterClause")
            .field("field", &self.field)
            .field("operator", &self.operator)
            .field("value", &"<redacted>")
            .finish()
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

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn parse_fields(value: &str) -> Result<BTreeSet<String>, QueryParseError> {
    if value.is_empty() {
        return Err(QueryParseError::Invalid);
    }
    let mut fields = BTreeSet::new();
    for field in value.split(',') {
        if fields.len() >= MAX_FIELDS
            || field.is_empty()
            || field.len() > MAX_FIELD_BYTES
            || !valid_id(field)
            || !fields.insert(field.to_owned())
        {
            return Err(QueryParseError::Invalid);
        }
    }
    Ok(fields)
}

fn parse_raw_filter(value: &str) -> Result<RawFilterClause, QueryParseError> {
    let (field, rest) = value.split_once(':').ok_or(QueryParseError::Invalid)?;
    let (operator, value) = rest.split_once(':').ok_or(QueryParseError::Invalid)?;
    if field.is_empty() || value.is_empty() || !valid_id(field) {
        return Err(QueryParseError::Invalid);
    }
    let operator = match operator {
        "equals" => CompiledQueryFilterOperator::Equals,
        "in" => CompiledQueryFilterOperator::In,
        "range" => CompiledQueryFilterOperator::Range,
        "is_null" => CompiledQueryFilterOperator::IsNull,
        "is_not_null" => CompiledQueryFilterOperator::IsNotNull,
        "prefix" => CompiledQueryFilterOperator::Prefix,
        _ => return Err(QueryParseError::Invalid),
    };
    Ok(RawFilterClause {
        field: field.to_owned(),
        operator,
        value: value.to_owned(),
    })
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Get => "get",
        Operation::List => "list",
        Operation::Create => "create",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
    }
}

fn query_kind_name(kind: CompiledQueryKind) -> &'static str {
    match kind {
        CompiledQueryKind::List => "list",
        CompiledQueryKind::Current => "current",
        CompiledQueryKind::AsOf => "as_of",
    }
}

fn query_parameters(kind: CompiledQueryKind) -> Value {
    let mut parameters = vec![
        query_parameter(
            "accessProfile",
            false,
            false,
            json!({"type": "string"}),
            "Select one compiled access profile.",
        ),
        query_parameter(
            "fields",
            false,
            false,
            json!({"type": "string"}),
            "Comma-separated subset of readable fields.",
        ),
        query_parameter(
            "filter",
            false,
            true,
            json!({"type": "string"}),
            "Repeatable field:operator:value filter clause.",
        ),
        query_parameter(
            "sort",
            false,
            false,
            json!({"type": "string"}),
            "One compiled sortable field, ascending only.",
        ),
        query_parameter(
            "pageSize",
            false,
            false,
            json!({"type": "integer", "minimum": 1}),
            "Bounded page size within the compiled maximum.",
        ),
        query_parameter(
            "cursor",
            false,
            false,
            json!({"type": "string"}),
            "Opaque continuation cursor for the next page.",
        ),
    ];
    if kind == CompiledQueryKind::AsOf {
        parameters.push(query_parameter(
            "asOf",
            true,
            false,
            json!({"type": "string", "format": "date-time"}),
            "Strict UTC RFC3339 instant for the as-of temporal query.",
        ));
    }
    Value::Array(parameters)
}

fn revision_parameters(kind: CompiledRevisionKind) -> Value {
    let mut parameters = vec![query_parameter(
        "accessProfile",
        false,
        false,
        json!({"type": "string"}),
        "Select one compiled access profile.",
    )];
    parameters.push(path_parameter(
        "record_id",
        json!({"type": "string", "format": "uuid"}),
        "Canonical record UUID.",
    ));
    if kind == CompiledRevisionKind::Detail {
        parameters.push(path_parameter(
            "revision",
            json!({"type": "integer", "format": "int64", "minimum": 1}),
            "Exact positive record revision.",
        ));
    }
    Value::Array(parameters)
}

fn query_parameter(
    name: &str,
    required: bool,
    repeatable: bool,
    schema: Value,
    description: &str,
) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": required,
        "description": description,
        "schema": schema,
        "explode": repeatable,
    })
}

fn path_parameter(name: &str, schema: Value, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": schema,
    })
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

fn exact_json(response: HeldReadResponse) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json");
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

fn exact_json_no_store(response: HeldReadResponse) -> Response {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "no-store"),
        ],
        response.body().to_vec(),
    )
        .into_response()
}

fn exact_mutation(response: &HeldResponse) -> Response {
    let mut builder = Response::builder().status(response.status());
    for (name, value) in response.headers() {
        let Ok(value) = HeaderValue::from_bytes(value) else {
            return unavailable();
        };
        builder = match name {
            PermittedResponseHeader::ContentType => builder.header(CONTENT_TYPE, value),
            PermittedResponseHeader::Etag => builder.header("etag", value),
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

fn parse_batch_body(body: &[u8], maximum_items: usize) -> Result<Vec<BatchMutationItem>, ()> {
    let value = parse_json_strict(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object.len() != 1 {
        return Err(());
    }
    let items = object.get("items").and_then(Value::as_array).ok_or(())?;
    if items.is_empty() || items.len() > maximum_items {
        return Err(());
    }
    items
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
        .collect()
}

fn access_profile_parameters() -> Value {
    Value::Array(vec![query_parameter(
        "accessProfile",
        false,
        false,
        json!({"type": "string"}),
        "Select one compiled access profile.",
    )])
}

fn batch_request_body(
    entity_id: &str,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    let mut item_schemas = Vec::new();
    if allow_create {
        item_schemas.push(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "data"],
            "properties": {
                "operation": {"const": "create"},
                "data": {"$ref": format!("#/components/schemas/{entity_id}")},
            }
        }));
    }
    if allow_patch {
        item_schemas.push(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "recordId", "ifMatch", "patch"],
            "properties": {
                "operation": {"const": "patch"},
                "recordId": {"type": "string", "format": "uuid"},
                "ifMatch": {"type": "string"},
                "patch": {"type": "array", "minItems": 1, "maxItems": 128},
            }
        }));
    }
    json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["items"],
                    "properties": {
                        "items": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": maximum_items,
                            "items": {"oneOf": item_schemas}
                        }
                    }
                }
            }
        }
    })
}

fn batch_response(
    entity_id: &str,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    let operations = [
        allow_create.then_some("create"),
        allow_patch.then_some("patch"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    json!({
        "200": {
            "description": "Atomic batch committed",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["results"],
                        "properties": {
                            "results": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": maximum_items,
                                "items": {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["operation", "id", "revision", "etag", "data"],
                                    "properties": {
                                        "operation": {"enum": operations},
                                        "id": {"type": "string", "format": "uuid"},
                                        "revision": {"type": "integer", "format": "int64", "minimum": 1},
                                        "etag": {"type": "string"},
                                        "data": {"$ref": format!("#/components/schemas/{entity_id}")},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
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
    value.len() > 5
        && value.len() <= 256
        && value.starts_with("\"rs-")
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn invalid_request() -> Response {
    fixed_problem(
        StatusCode::BAD_REQUEST,
        "request.invalid",
        "The mutation request is invalid.",
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
        MutationError::Unavailable => fixed_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "service.unavailable",
            "The Registry mutation service is unavailable.",
        ),
    }
}

fn fixed_problem(status: StatusCode, code: &'static str, detail: &'static str) -> Response {
    Problem::new(
        &format!("urn:registry-server:problem:{code}"),
        status.canonical_reason().unwrap_or("Request failed"),
        status,
    )
    .detail(detail)
    .with_extra("code", Value::String(code.to_owned()))
    .into_response()
}

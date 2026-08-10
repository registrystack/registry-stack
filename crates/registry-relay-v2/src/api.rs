// SPDX-License-Identifier: Apache-2.0
//! Fixed Relay V2 HTTP handlers over the immutable compiled kernel.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, VARY};
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
use chrono::{DateTime, NaiveDate};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_sqlite::{ErrorKind as SqliteErrorKind, ResultRow, Value as SqlValue};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::artifacts::GeneratedArtifact;
use crate::audit::{AuditContext, AuditOutcome, PrincipalKind, RelayAudit, RowBoundaryKind};
use crate::auth::{bearer_token, Authorization, AuthorizationError, Principal};
use crate::contract::{DataType, Handling, OrderedMap, Visibility};
use crate::cursor::{
    decode as decode_cursor, encode as encode_cursor, now_unix_seconds, require_same_request,
    CursorBindings, CursorPayload, CursorValue,
};
use crate::model::{
    CompiledAccess, CompiledAccessProfile, CompiledOperation, CompiledResource, OperationKind,
    RowAuthoritySource,
};
use crate::problem::{ProblemCode, TraceContext};
use crate::server::{uri_within_bound, RelayService};
use crate::sqlite_runtime::{OperationQuery, SourceRevision, SqliteRuntimeError};
use crate::transform;

const PRODUCT_NAME: &str = "Registry Relay";
const PRODUCT_VERSION: &str = "2";
const API_BINDING_NAME: &str = "registry-relay-http";
const API_BINDING_VERSION: &str = "v2";
const METADATA_DEFAULT_PAGE_SIZE: usize = 50;
const METADATA_MAXIMUM_PAGE_SIZE: usize = 100;
const MAXIMUM_SERIALIZED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseFormat {
    Json,
    JsonLd,
}

impl ResponseFormat {
    const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::JsonLd => "application/ld+json",
        }
    }
}

#[derive(Clone)]
struct Access {
    principal: Option<Principal>,
    authorization: Authorization,
    access_profile: CompiledAccessProfile,
}

pub async fn health() -> Response<Body> {
    minimal_status("ok")
}

pub async fn ready(State(service): State<Arc<RelayService>>) -> Response<Body> {
    if service.is_ready().await {
        minimal_status("ready")
    } else {
        ProblemCode::ServiceNotReady.response(&TraceContext::server_created())
    }
}

pub async fn openapi(
    State(service): State<Arc<RelayService>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if let Some(response) = preflight_public(&service, &headers, &uri, &trace).await {
        return response;
    }
    let Some(artifact) = service.artifacts.get("openapi.public.json") else {
        return ProblemCode::Internal.response(&trace);
    };
    static_bytes_response(
        &artifact.content,
        "application/json",
        true,
        &headers,
        &trace,
    )
}

pub async fn service_metadata(
    State(service): State<Arc<RelayService>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return ProblemCode::UriTooLong.response(&trace);
    }
    let principal = match optional_principal(&service, &headers).await {
        Ok(value) => value,
        Err(code) => return code.response(&trace),
    };
    let mut capabilities = Vec::new();
    if service.registry.metadata_visibility.resources != Visibility::OperatorOnly {
        for resource in &service.registry.resources {
            let operations = match visible_operations(&service, resource, principal.as_ref()).await
            {
                Ok(value) => value,
                Err(ProblemCode::MissingCredential) => Vec::new(),
                Err(code) => return code.response(&trace),
            };
            capabilities.extend(operations.into_iter().map(|(operation, access_profile)| {
                capability(&service, resource, operation, access_profile)
            }));
        }
    }
    let alignment_targets = service
        .metadata
        .alignment_targets
        .iter()
        .map(|target| {
            json!({
                "name": target.name,
                "version": target.version,
                "status": target.status,
                "cfrTarget": target.cfr_target,
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "registryIdentifier": service.registry.registry_identifier,
        "name": service.registry.registry_name,
        "authority": {
            "identifier": service.metadata.authority.identifier,
            "name": service.metadata.authority.name,
        },
        "operator": service.metadata.operator.as_ref().map(|item| json!({
            "identifier": item.identifier,
            "name": item.name,
        })),
        "authoritativeScope": service.metadata.authoritative_scope,
        "product": {"name": PRODUCT_NAME, "version": PRODUCT_VERSION},
        "apiBinding": {"name": API_BINDING_NAME, "version": API_BINDING_VERSION},
        "alignmentTargets": alignment_targets,
        "capabilities": capabilities,
        "links": {
            "self": absolute(&service.registry.base_uri, "/v2"),
            "resources": absolute(&service.registry.base_uri, "/v2/resources"),
            "openapi": absolute(&service.registry.base_uri, "/openapi.json"),
        }
    });
    json_metadata_response(
        value,
        service.registry.metadata_visibility.resources == Visibility::Public,
        &headers,
        &trace,
    )
}

pub async fn resource_list(
    State(service): State<Arc<RelayService>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return ProblemCode::UriTooLong.response(&trace);
    }
    let principal = match optional_principal(&service, &headers).await {
        Ok(value) => value,
        Err(code) => return code.response(&trace),
    };
    let mut visible = match visible_resources(&service, principal.as_ref()).await {
        Ok(value) => value,
        Err(code) => return code.response(&trace),
    };
    visible.sort_by(|(left, _), (right, _)| left.id.cmp(&right.id));
    let query = match parse_query(uri.query()) {
        Ok(value) => value,
        Err(code) => return code.response(&trace),
    };
    let (page_size, start) = if query.iter().any(|(name, _)| name == "cursor") {
        if query.len() != 1 || query[0].0 != "cursor" || query[0].1.is_empty() {
            return ProblemCode::CursorInvalid.response(&trace);
        }
        let Some(key) = service.cursor_key.as_ref() else {
            return ProblemCode::CursorInvalid.response(&trace);
        };
        let payload = match decode_cursor(key, &query[0].1, now_unix_seconds()) {
            Ok(value) => value,
            Err(_) => return ProblemCode::CursorInvalid.response(&trace),
        };
        let request = match metadata_cursor_template(&service, &visible) {
            Ok(value) => value,
            Err(code) => return code.response(&trace),
        };
        if require_same_request(&payload, &request).is_err()
            || payload.page_size == 0
            || usize::try_from(payload.page_size)
                .ok()
                .is_none_or(|value| value > METADATA_MAXIMUM_PAGE_SIZE)
        {
            return ProblemCode::CursorInvalid.response(&trace);
        }
        let Some(position) = visible
            .iter()
            .position(|(resource, _)| resource.id == payload.last_record_identifier)
        else {
            return ProblemCode::CursorInvalid.response(&trace);
        };
        (
            usize::try_from(payload.page_size).unwrap_or(METADATA_MAXIMUM_PAGE_SIZE),
            position.saturating_add(1),
        )
    } else {
        if query.iter().any(|(name, _)| name != "pageSize") {
            return ProblemCode::ConsultationInvalidRequest.response(&trace);
        }
        let page_size = match one_parameter(&query, "pageSize") {
            Ok(Some(value)) => match value.parse::<usize>() {
                Ok(value) if (1..=METADATA_MAXIMUM_PAGE_SIZE).contains(&value) => value,
                _ => return ProblemCode::ConsultationInvalidRequest.response(&trace),
            },
            Ok(None) => METADATA_DEFAULT_PAGE_SIZE,
            Err(code) => return code.response(&trace),
        };
        (page_size, 0)
    };
    let mut page = visible
        .iter()
        .skip(start)
        .take(page_size.saturating_add(1))
        .cloned()
        .collect::<Vec<_>>();
    let has_next = page.len() > page_size;
    if has_next {
        page.pop();
    }
    let next_cursor = if has_next {
        let Some((last, _)) = page.last() else {
            return ProblemCode::Internal.response(&trace);
        };
        match metadata_next_cursor(&service, &visible, page_size, &last.id) {
            Ok(value) => Some(value),
            Err(code) => return code.response(&trace),
        }
    } else {
        None
    };
    let items = page
        .into_iter()
        .map(|(resource, operations)| resource_document(&service, resource, &operations))
        .collect::<Vec<_>>();
    json_metadata_response(
        json!({
            "items": items,
            "pageInfo": {"nextCursor": next_cursor},
            "meta": {"registryIdentifier": service.registry.registry_identifier},
        }),
        service.registry.metadata_visibility.resources == Visibility::Public,
        &headers,
        &trace,
    )
}

pub async fn resource_metadata(
    State(service): State<Arc<RelayService>>,
    Path(resource_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return ProblemCode::UriTooLong.response(&trace);
    }
    let principal = match optional_principal(&service, &headers).await {
        Ok(value) => value,
        Err(code) => return code.response(&trace),
    };
    let Some(resource) = service
        .registry
        .resources
        .iter()
        .find(|item| item.id == resource_id)
    else {
        if principal.is_none() && protected_metadata_exists(&service) {
            return ProblemCode::MissingCredential.response(&trace);
        }
        return ProblemCode::ResourceNotFound.response(&trace);
    };
    let operations = match visible_operations(&service, resource, principal.as_ref()).await {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => return ProblemCode::ResourceNotFound.response(&trace),
        Err(code) => return code.response(&trace),
    };
    json_metadata_response(
        json!({
            "data": resource_document(&service, resource, &operations),
            "meta": {"registryIdentifier": service.registry.registry_identifier},
        }),
        service.registry.metadata_visibility.resources == Visibility::Public,
        &headers,
        &trace,
    )
}

pub async fn artifact(
    State(service): State<Arc<RelayService>>,
    Path(artifact_identifier): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return ProblemCode::UriTooLong.response(&trace);
    }
    let principal = match optional_principal(&service, &headers).await {
        Ok(value) => value,
        Err(code) => return code.response(&trace),
    };
    let Some(artifact) = service
        .artifacts
        .artifacts
        .iter()
        .find(|item| item.id == artifact_identifier)
    else {
        if principal.is_none() && service.artifacts.artifacts.iter().any(protected_artifact) {
            return ProblemCode::MissingCredential.response(&trace);
        }
        return ProblemCode::ResourceNotFound.response(&trace);
    };
    match artifact.visibility {
        Visibility::OperatorOnly => return ProblemCode::ResourceNotFound.response(&trace),
        Visibility::Public => {}
        Visibility::OperationBound => {
            let Some(principal) = principal.as_ref() else {
                return ProblemCode::MissingCredential.response(&trace);
            };
            let Some(identifier) = artifact.operation_identifier.as_deref() else {
                return ProblemCode::ResourceNotFound.response(&trace);
            };
            let Some(operation) = find_operation_by_id(&service, identifier) else {
                return ProblemCode::ResourceNotFound.response(&trace);
            };
            let Some(access_profile_identifier) = artifact.access_profile_identifier.as_deref()
            else {
                return ProblemCode::ResourceNotFound.response(&trace);
            };
            let Some(access_profile) = operation
                .access_profiles
                .iter()
                .find(|access_profile| access_profile.id == access_profile_identifier)
            else {
                return ProblemCode::ResourceNotFound.response(&trace);
            };
            let Some(authenticator) = &service.authenticator else {
                return ProblemCode::ResourceNotFound.response(&trace);
            };
            if authenticator
                .authorize(&access_profile.access, Some(principal))
                .is_err()
            {
                return ProblemCode::ResourceNotFound.response(&trace);
            }
        }
    }
    static_bytes_response(
        &artifact.content,
        &artifact.media_type,
        artifact.visibility == Visibility::Public,
        &headers,
        &trace,
    )
}

pub async fn record_list(
    State(service): State<Arc<RelayService>>,
    Path(resource_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    let principal = match authenticate_data_request(&service, &headers, &trace).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some((resource, operation)) = find_operation(&service, &resource_id, |kind| {
        matches!(kind, OperationKind::List)
    }) else {
        return unknown_data_route(
            &service,
            principal.as_ref(),
            uri.query(),
            &trace,
            OperationClass::List,
        )
        .await;
    };
    let access = match access_operation(
        &service,
        resource,
        operation,
        uri.query(),
        principal,
        &trace,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !uri_within_bound(&uri) {
        return refuse_known(
            &service,
            resource,
            operation,
            Some(&access),
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    if rejects_caller_purpose(&headers) {
        return refuse_known(
            &service,
            resource,
            operation,
            Some(&access),
            AuditOutcome::InvalidRequest,
            ProblemCode::ConsultationInvalidRequest,
            &trace,
        )
        .await;
    }
    let response_format = match negotiate(&headers) {
        Ok(value) => value,
        Err(code) => {
            return refuse_known(
                &service,
                resource,
                operation,
                Some(&access),
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await
        }
    };
    let query = match prepare_list(&service, resource, operation, &access, uri.query()) {
        Ok(value) => value,
        Err(code) => {
            return refuse_known(
                &service,
                resource,
                operation,
                Some(&access),
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await
        }
    };
    if let Some(response) = quota_refusal(
        &service,
        resource,
        operation,
        &access,
        &query.selected_fields,
        &trace,
    )
    .await
    {
        return response;
    }
    let audit = audit_context(
        &service,
        resource,
        operation,
        Some(&access),
        query.selected_fields.clone(),
        &trace,
    );
    if service.audit.attempt(&audit).await.is_err() {
        return ProblemCode::AuditUnavailable.response(&trace);
    }
    let result = service
        .sqlite
        .execute(
            &operation.identifier,
            &access.access_profile.id,
            OperationQuery {
                filters: query.filters.clone(),
                row_authority: access.authorization.row_authority.clone(),
                after_order: query.after_order.clone(),
                fetch_limit: Some(query.page_size.saturating_add(1)),
                ..OperationQuery::default()
            },
        )
        .await;
    let result = match result {
        Ok(value) => value,
        Err(error) => return source_failure(&service.audit, &audit, error, &trace).await,
    };
    let mut rows = result.rows;
    let page_size = usize::try_from(query.page_size).unwrap_or(usize::MAX);
    let has_next = rows.len() > page_size;
    let mut items = Vec::with_capacity(rows.len().min(page_size));
    for (index, row) in rows.iter().enumerate() {
        if cursor_order_values(&operation.query.order_by, row).is_none() {
            return source_shape_failure(&service.audit, &audit, &trace).await;
        }
        let record = match record_value(
            &service,
            resource,
            &access.access_profile,
            row,
            &query.selected_fields,
        ) {
            Ok(value) => value,
            Err(RecordError::InvalidSource) => {
                return source_shape_failure(&service.audit, &audit, &trace).await
            }
            Err(RecordError::InvalidCore) => {
                return source_shape_failure(&service.audit, &audit, &trace).await
            }
        };
        if index < page_size {
            items.push(record);
        }
    }
    if has_next {
        rows.truncate(page_size);
    }
    let next_cursor = if has_next {
        let Some(last) = rows.last() else {
            return terminal_problem(
                &service.audit,
                &audit,
                AuditOutcome::InternalFailed,
                ProblemCode::Internal,
                &trace,
            )
            .await;
        };
        match next_cursor(
            &service,
            operation,
            &access,
            &query,
            last,
            &result.source_revision,
        ) {
            Ok(value) => Some(value),
            Err(_) => return source_shape_failure(&service.audit, &audit, &trace).await,
        }
    } else {
        None
    };
    let mut document = json!({
        "items": items,
        "pageInfo": {"nextCursor": next_cursor},
        "meta": record_meta(
            &service,
            resource,
            operation,
            &access.access_profile,
            &query.selected_fields,
            &result.source_revision,
        ),
    });
    apply_json_ld(
        &service,
        resource,
        &access.access_profile,
        response_format,
        &mut document,
    );
    release_document(
        &service,
        &audit,
        document,
        response_format,
        cacheable(&access.access_profile, &result.source_revision),
        &headers,
        &trace,
    )
    .await
}

pub async fn record_read(
    State(service): State<Arc<RelayService>>,
    Path((resource_id, record_identifier)): Path<(String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    let principal = match authenticate_data_request(&service, &headers, &trace).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some((resource, operation)) = find_operation(&service, &resource_id, |kind| {
        matches!(kind, OperationKind::Read)
    }) else {
        return unknown_data_route(
            &service,
            principal.as_ref(),
            uri.query(),
            &trace,
            OperationClass::Read,
        )
        .await;
    };
    let access = match access_operation(
        &service,
        resource,
        operation,
        uri.query(),
        principal,
        &trace,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !uri_within_bound(&uri) {
        return refuse_known(
            &service,
            resource,
            operation,
            Some(&access),
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    if !valid_record_identifier(&record_identifier) {
        return refuse_known(
            &service,
            resource,
            operation,
            Some(&access),
            AuditOutcome::Unresolved,
            ProblemCode::ConsultationUnresolved,
            &trace,
        )
        .await;
    }
    single_operation(
        &service,
        resource,
        operation,
        access,
        SingleRequest {
            headers: &headers,
            query_text: uri.query(),
            query: OperationQuery {
                record_identifier: Some(record_identifier),
                ..OperationQuery::default()
            },
            prevalidated: None,
            quota_admitted: false,
            trace: &trace,
        },
    )
    .await
}

pub async fn record_lookup(
    State(service): State<Arc<RelayService>>,
    Path((resource_id, lookup_id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response<Body> {
    let trace = TraceContext::from_headers(request.headers());
    let principal = match authenticate_data_request(&service, request.headers(), &trace).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some((resource, operation)) = find_operation(
        &service,
        &resource_id,
        |kind| matches!(kind, OperationKind::Lookup { name } if name == &lookup_id),
    ) else {
        return unknown_data_route(
            &service,
            principal.as_ref(),
            request.uri().query(),
            &trace,
            OperationClass::Lookup,
        )
        .await;
    };
    let access = match access_operation(
        &service,
        resource,
        operation,
        request.uri().query(),
        principal,
        &trace,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !uri_within_bound(request.uri()) {
        return refuse_known(
            &service,
            resource,
            operation,
            Some(&access),
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    if rejects_caller_purpose(request.headers()) {
        return refuse_known(
            &service,
            resource,
            operation,
            Some(&access),
            AuditOutcome::InvalidRequest,
            ProblemCode::ConsultationInvalidRequest,
            &trace,
        )
        .await;
    }
    let response_format = match negotiate(request.headers()) {
        Ok(value) => value,
        Err(code) => {
            return refuse_known(
                &service,
                resource,
                operation,
                Some(&access),
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await
        }
    };
    let fields = match selected_fields(
        resource,
        operation,
        &access.access_profile,
        request.uri().query(),
    ) {
        Ok(value) => value,
        Err(code) => {
            return refuse_known(
                &service,
                resource,
                operation,
                Some(&access),
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await
        }
    };
    if !is_json_content_type(request.headers()) {
        return refuse_known(
            &service,
            resource,
            operation,
            Some(&access),
            AuditOutcome::InvalidRequest,
            ProblemCode::UnsupportedMediaType,
            &trace,
        )
        .await;
    }
    if let Some(response) =
        quota_refusal(&service, resource, operation, &access, &fields, &trace).await
    {
        return response;
    }
    let (parts, body) = request.into_parts();
    let Some(maximum) = operation.query.maximum_request_body_bytes else {
        return ProblemCode::Internal.response(&trace);
    };
    let maximum = match usize::try_from(maximum) {
        Ok(value) => value,
        Err(_) => return ProblemCode::Internal.response(&trace),
    };
    let bytes = match tokio::time::timeout(service.request_timeout, to_bytes(body, maximum)).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => {
            return refuse_known(
                &service,
                resource,
                operation,
                Some(&access),
                AuditOutcome::InvalidRequest,
                ProblemCode::BodyTooLarge,
                &trace,
            )
            .await
        }
        Err(_) => {
            return refuse_known(
                &service,
                resource,
                operation,
                Some(&access),
                AuditOutcome::TimedOut,
                ProblemCode::Timeout,
                &trace,
            )
            .await
        }
    };
    let selectors = match parse_selectors(&service, operation, &bytes) {
        Ok(value) => value,
        Err(code) => {
            return refuse_known(
                &service,
                resource,
                operation,
                Some(&access),
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await
        }
    };
    single_operation(
        &service,
        resource,
        operation,
        access,
        SingleRequest {
            headers: &parts.headers,
            query_text: parts.uri.query(),
            query: OperationQuery {
                selectors,
                ..OperationQuery::default()
            },
            prevalidated: Some((response_format, fields)),
            quota_admitted: true,
            trace: &trace,
        },
    )
    .await
}

pub async fn not_found(
    State(service): State<Arc<RelayService>>,
    headers: HeaderMap,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if let Err(code) = optional_principal(&service, &headers).await {
        return code.response(&trace);
    }
    ProblemCode::ResourceNotFound.response(&trace)
}

struct SingleRequest<'a> {
    headers: &'a HeaderMap,
    query_text: Option<&'a str>,
    query: OperationQuery,
    prevalidated: Option<(ResponseFormat, Vec<String>)>,
    quota_admitted: bool,
    trace: &'a TraceContext,
}

async fn single_operation(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access: Access,
    mut request: SingleRequest<'_>,
) -> Response<Body> {
    let headers = request.headers;
    let trace = request.trace;
    let (representation, fields) = match request.prevalidated.take() {
        Some(value) => value,
        None => {
            if rejects_caller_purpose(headers) {
                return refuse_known(
                    service,
                    resource,
                    operation,
                    Some(&access),
                    AuditOutcome::InvalidRequest,
                    ProblemCode::ConsultationInvalidRequest,
                    trace,
                )
                .await;
            }
            let representation = match negotiate(headers) {
                Ok(value) => value,
                Err(code) => {
                    return refuse_known(
                        service,
                        resource,
                        operation,
                        Some(&access),
                        AuditOutcome::InvalidRequest,
                        code,
                        trace,
                    )
                    .await
                }
            };
            let fields = match selected_fields(
                resource,
                operation,
                &access.access_profile,
                request.query_text,
            ) {
                Ok(value) => value,
                Err(code) => {
                    return refuse_known(
                        service,
                        resource,
                        operation,
                        Some(&access),
                        AuditOutcome::InvalidRequest,
                        code,
                        trace,
                    )
                    .await
                }
            };
            (representation, fields)
        }
    };
    if !request.quota_admitted {
        if let Some(response) =
            quota_refusal(service, resource, operation, &access, &fields, trace).await
        {
            return response;
        }
    }
    let audit = audit_context(
        service,
        resource,
        operation,
        Some(&access),
        fields.clone(),
        trace,
    );
    if service.audit.attempt(&audit).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    request.query.row_authority = access.authorization.row_authority.clone();
    let result = service
        .sqlite
        .execute(
            &operation.identifier,
            &access.access_profile.id,
            request.query,
        )
        .await;
    let result = match result {
        Ok(value) => value,
        Err(error) => return source_failure(&service.audit, &audit, error, trace).await,
    };
    if result.rows.len() > 1 && matches!(&operation.kind, OperationKind::Read) {
        return source_shape_failure(&service.audit, &audit, trace).await;
    }
    if result.rows.len() != 1 {
        if service
            .audit
            .terminal(&audit, AuditOutcome::Unresolved, None)
            .await
            .is_err()
        {
            return ProblemCode::AuditUnavailable.response(trace);
        }
        return ProblemCode::ConsultationUnresolved.response(trace);
    }
    let record = match record_value(
        service,
        resource,
        &access.access_profile,
        &result.rows[0],
        &fields,
    ) {
        Ok(value) => value,
        Err(RecordError::InvalidSource | RecordError::InvalidCore) => {
            return source_shape_failure(&service.audit, &audit, trace).await;
        }
    };
    let mut document = json!({
        "data": record,
        "meta": record_meta(
            service,
            resource,
            operation,
            &access.access_profile,
            &fields,
            &result.source_revision,
        ),
    });
    apply_json_ld(
        service,
        resource,
        &access.access_profile,
        representation,
        &mut document,
    );
    release_document(
        service,
        &audit,
        document,
        representation,
        cacheable(&access.access_profile, &result.source_revision),
        headers,
        trace,
    )
    .await
}

async fn access_operation(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    query: Option<&str>,
    principal: Option<Principal>,
    trace: &TraceContext,
) -> Result<Access, Response<Body>> {
    let selected = match select_access_profile(operation, query) {
        Ok(value) => value,
        Err(ProblemCode::ResourceNotFound) => {
            return Err(refuse_unknown(
                service,
                principal_kind(principal.as_ref()),
                AuditOutcome::NotFound,
                ProblemCode::ResourceNotFound,
                trace,
            )
            .await);
        }
        Err(code) => {
            return Err(refuse_before_access_profile(
                service,
                resource,
                operation,
                principal_kind(principal.as_ref()),
                AuditOutcome::InvalidRequest,
                code,
                trace,
            )
            .await);
        }
    };
    let access_profile = selected.access_profile;
    let explicit = selected.explicit;
    let authorization = match &service.authenticator {
        Some(authenticator) => authenticator.authorize(&access_profile.access, principal.as_ref()),
        None => match access_profile.access {
            CompiledAccess::Public => Ok(Authorization {
                row_authority: None,
                purpose: None,
            }),
            CompiledAccess::Protected { .. } => Err(AuthorizationError::AuthenticationRequired),
        },
    };
    match authorization {
        Ok(authorization) => Ok(Access {
            principal,
            authorization,
            access_profile: access_profile.clone(),
        }),
        Err(error) => {
            if error == AuthorizationError::AuthenticationRequired && explicit {
                return Err(refuse_unknown(
                    service,
                    PrincipalKind::Anonymous,
                    AuditOutcome::NotFound,
                    ProblemCode::ResourceNotFound,
                    trace,
                )
                .await);
            }
            if error == AuthorizationError::ScopeDenied {
                return Err(refuse_unknown(
                    service,
                    PrincipalKind::Authenticated,
                    AuditOutcome::NotFound,
                    ProblemCode::ResourceNotFound,
                    trace,
                )
                .await);
            }
            let (code, outcome) = match error {
                AuthorizationError::AuthenticationRequired => (
                    ProblemCode::MissingCredential,
                    AuditOutcome::MissingCredential,
                ),
                AuthorizationError::ScopeDenied
                | AuthorizationError::PurposeDenied
                | AuthorizationError::BindingDenied => {
                    (ProblemCode::ConsultationDenied, AuditOutcome::Denied)
                }
            };
            let denied_access = Access {
                principal,
                authorization: Authorization {
                    row_authority: None,
                    purpose: None,
                },
                access_profile: access_profile.clone(),
            };
            Err(refuse_known(
                service,
                resource,
                operation,
                Some(&denied_access),
                outcome,
                code,
                trace,
            )
            .await)
        }
    }
}

async fn authenticate_data_request(
    service: &RelayService,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Result<Option<Principal>, Response<Body>> {
    match optional_principal(service, headers).await {
        Ok(principal) => Ok(principal),
        Err(code) => Err(refuse_unknown(
            service,
            PrincipalKind::Unknown,
            AuditOutcome::InvalidCredential,
            code,
            trace,
        )
        .await),
    }
}

async fn optional_principal(
    service: &RelayService,
    headers: &HeaderMap,
) -> Result<Option<Principal>, ProblemCode> {
    let token = bearer_token(headers).map_err(|_| ProblemCode::InvalidCredential)?;
    let Some(token) = token else {
        return Ok(None);
    };
    let authenticator = service
        .authenticator
        .as_ref()
        .ok_or(ProblemCode::InvalidCredential)?;
    authenticator
        .authenticate(token)
        .await
        .map(Some)
        .map_err(|_| ProblemCode::InvalidCredential)
}

async fn preflight_public(
    service: &RelayService,
    headers: &HeaderMap,
    uri: &Uri,
    trace: &TraceContext,
) -> Option<Response<Body>> {
    if !uri_within_bound(uri) {
        return Some(ProblemCode::UriTooLong.response(trace));
    }
    if optional_principal(service, headers).await.is_err() {
        return Some(ProblemCode::InvalidCredential.response(trace));
    }
    None
}

#[derive(Clone, Copy)]
enum OperationClass {
    List,
    Read,
    Lookup,
}

async fn unknown_data_route(
    service: &RelayService,
    principal: Option<&Principal>,
    query: Option<&str>,
    trace: &TraceContext,
    class: OperationClass,
) -> Response<Body> {
    let explicit_access_profile = match access_profile_parameter(query) {
        Ok(Some(identifier)) if valid_access_profile_identifier(&identifier) => true,
        Ok(Some(_)) | Err(_) => {
            return refuse_unknown(
                service,
                principal_kind(principal),
                AuditOutcome::InvalidRequest,
                ProblemCode::AccessProfileInvalid,
                trace,
            )
            .await;
        }
        Ok(None) => false,
    };
    if explicit_access_profile {
        return refuse_unknown(
            service,
            principal_kind(principal),
            AuditOutcome::NotFound,
            ProblemCode::ResourceNotFound,
            trace,
        )
        .await;
    }
    let protected = service.registry.resources.iter().any(|resource| {
        resource.operations.iter().any(|operation| {
            class_matches(&operation.kind, class)
                && operation.access_profiles.iter().any(|access_profile| {
                    matches!(access_profile.access, CompiledAccess::Protected { .. })
                })
        })
    });
    if protected && principal.is_none() {
        return refuse_unknown(
            service,
            PrincipalKind::Unknown,
            AuditOutcome::MissingCredential,
            ProblemCode::MissingCredential,
            trace,
        )
        .await;
    }
    refuse_unknown(
        service,
        if principal.is_some() {
            PrincipalKind::Authenticated
        } else {
            PrincipalKind::Anonymous
        },
        AuditOutcome::NotFound,
        ProblemCode::ResourceNotFound,
        trace,
    )
    .await
}

fn class_matches(kind: &OperationKind, class: OperationClass) -> bool {
    matches!(
        (kind, class),
        (OperationKind::List, OperationClass::List)
            | (OperationKind::Read, OperationClass::Read)
            | (OperationKind::Lookup { .. }, OperationClass::Lookup)
    )
}

async fn refuse_unknown(
    service: &RelayService,
    principal_kind: PrincipalKind,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    let audit = unknown_audit_context(service, trace, principal_kind);
    if service.audit.refusal(&audit, outcome).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

async fn refuse_known(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access: Option<&Access>,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    let context = audit_context(service, resource, operation, access, Vec::new(), trace);
    if service.audit.refusal(&context, outcome).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

async fn refuse_before_access_profile(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    principal_kind: PrincipalKind,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    let mut context = audit_context(service, resource, operation, None, Vec::new(), trace);
    context.principal_kind = principal_kind;
    if service.audit.refusal(&context, outcome).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

async fn quota_refusal(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access: &Access,
    fields: &[String],
    trace: &TraceContext,
) -> Option<Response<Body>> {
    let denied = service
        .quota
        .as_ref()
        .is_some_and(|limiter| !limiter.admit(&operation.identifier));
    if !denied {
        return None;
    }
    let context = audit_context(
        service,
        resource,
        operation,
        Some(access),
        fields.to_vec(),
        trace,
    );
    if service
        .audit
        .refusal(&context, AuditOutcome::RateLimited)
        .await
        .is_err()
    {
        return Some(ProblemCode::AuditUnavailable.response(trace));
    }
    Some(ProblemCode::RateLimited.response(trace))
}

fn audit_context(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access: Option<&Access>,
    selected_properties: Vec<String>,
    trace: &TraceContext,
) -> AuditContext {
    AuditContext {
        operation_id: RelayAudit::operation_id(),
        trace_id: trace.trace_id.clone(),
        registry_identifier: service.registry.registry_identifier.clone(),
        resource_identifier: Some(resource.id.clone()),
        operation_identifier: Some(operation.identifier.clone()),
        access_rule_revision: access.map(|access| access_revision(&access.access_profile)),
        purpose: access.and_then(|access| access.authorization.purpose.clone()),
        row_boundary_kind: access.map_or(RowBoundaryKind::Unknown, |access| {
            row_boundary(&access.access_profile)
        }),
        access_profile: access.map(|access| access.access_profile.id.clone()),
        disclosure_profile: access.map(|access| access.access_profile.disclosure_profile.clone()),
        processing_description_identifiers: processing_description_identifiers(resource, operation),
        selected_properties,
        processing_handling: access
            .map(|access| handling_label(access.access_profile.processing_handling).into()),
        disclosure_handling: access
            .map(|access| handling_label(access.access_profile.disclosure_handling).into()),
        transform_identifiers: access.map_or_else(Vec::new, |access| {
            transform_identifiers(&access.access_profile)
        }),
        contract_revision: service.registry.contract_revision.clone(),
        source_revision: service
            .sqlite
            .source_revision(&operation.identifier)
            .cloned(),
        principal_kind: access.map_or(PrincipalKind::Anonymous, |access| {
            principal_kind(access.principal.as_ref())
        }),
    }
}

fn principal_kind(principal: Option<&Principal>) -> PrincipalKind {
    if principal.is_some() {
        PrincipalKind::Authenticated
    } else {
        PrincipalKind::Anonymous
    }
}

fn unknown_audit_context(
    service: &RelayService,
    trace: &TraceContext,
    principal_kind: PrincipalKind,
) -> AuditContext {
    AuditContext {
        operation_id: RelayAudit::operation_id(),
        trace_id: trace.trace_id.clone(),
        registry_identifier: service.registry.registry_identifier.clone(),
        resource_identifier: None,
        operation_identifier: None,
        access_rule_revision: None,
        purpose: None,
        row_boundary_kind: RowBoundaryKind::Unknown,
        access_profile: None,
        disclosure_profile: None,
        processing_description_identifiers: Vec::new(),
        selected_properties: Vec::new(),
        processing_handling: None,
        disclosure_handling: None,
        transform_identifiers: Vec::new(),
        contract_revision: service.registry.contract_revision.clone(),
        source_revision: None,
        principal_kind,
    }
}

fn processing_description_identifiers(
    resource: &CompiledResource,
    operation: &CompiledOperation,
) -> Vec<String> {
    let reference = match &operation.kind {
        OperationKind::List => "list".to_owned(),
        OperationKind::Read => "read".to_owned(),
        OperationKind::Lookup { name } => format!("lookup:{name}"),
    };
    resource
        .processing_descriptions
        .iter()
        .filter(|description| description.operation_refs.contains(&reference))
        .map(|description| description.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn access_revision(access_profile: &CompiledAccessProfile) -> String {
    let value = serde_json::to_value(&access_profile.access)
        .expect("compiled access-profile rule serializes");
    let bytes = canonicalize_json(&value).expect("compiled access-profile rule canonicalizes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn transform_identifiers(access_profile: &CompiledAccessProfile) -> Vec<String> {
    access_profile
        .transform_inventory
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(_, identifier)| identifier.to_owned())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn row_boundary(access_profile: &CompiledAccessProfile) -> RowBoundaryKind {
    match &access_profile.access {
        CompiledAccess::Protected {
            row_binding: Some(binding),
            ..
        } => match binding.source {
            RowAuthoritySource::Principal => RowBoundaryKind::Principal,
            RowAuthoritySource::Claim(_) => RowBoundaryKind::VerifiedClaim,
        },
        CompiledAccess::Public
        | CompiledAccess::Protected {
            row_binding: None, ..
        } => RowBoundaryKind::None,
    }
}

fn handling_label(value: Handling) -> &'static str {
    match value {
        Handling::Public => "public",
        Handling::Internal => "internal",
        Handling::Confidential => "confidential",
        Handling::Restricted => "restricted",
    }
}

struct PreparedList {
    page_size: u32,
    filters: BTreeMap<String, SqlValue>,
    selected_fields: Vec<String>,
    after_order: Option<Vec<SqlValue>>,
}

struct SelectedAccessProfile<'a> {
    access_profile: &'a CompiledAccessProfile,
    explicit: bool,
}

fn select_access_profile<'a>(
    operation: &'a CompiledOperation,
    query: Option<&str>,
) -> Result<SelectedAccessProfile<'a>, ProblemCode> {
    let requested = access_profile_parameter(query)?;
    let identifier = requested
        .as_deref()
        .unwrap_or(&operation.default_access_profile);
    if !valid_access_profile_identifier(identifier) {
        return Err(ProblemCode::AccessProfileInvalid);
    }
    let explicit = requested.is_some();
    operation
        .access_profiles
        .iter()
        .find(|access_profile| access_profile.id == identifier)
        .map(|access_profile| SelectedAccessProfile {
            access_profile,
            explicit,
        })
        .ok_or(ProblemCode::ResourceNotFound)
}

/// Extract only the access-profile selector before URI-shape refusal.
///
/// This scans the already-buffered query in place and decodes only bounded
/// candidate names and the one bounded access-profile value. It therefore
/// preserves exact-profile authorization for an oversized URI without
/// allocating or decoding unrelated attacker-controlled query values.
fn access_profile_parameter(query: Option<&str>) -> Result<Option<String>, ProblemCode> {
    // `representation` is the longest decoded current-or-retired selector
    // name. Three encoded bytes per decoded byte covers its fully
    // percent-encoded form without permitting an unbounded name decode.
    const MAXIMUM_ENCODED_NAME_BYTES: usize = "representation".len() * 3;
    const MAXIMUM_ENCODED_VALUE_BYTES: usize = 128 * 3;

    let Some(query) = query else {
        return Ok(None);
    };
    let mut requested = None;
    for parameter in query.split('&') {
        let (raw_name, raw_value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if raw_name.len() > MAXIMUM_ENCODED_NAME_BYTES {
            continue;
        }
        if !valid_percent_encoding(raw_name.as_bytes()) {
            // A malformed unrelated parameter remains an ordinary query-shape
            // error after authorization. It cannot decode to the selector.
            continue;
        }
        let name = decode_bounded_query_component(raw_name, MAXIMUM_ENCODED_NAME_BYTES)?;
        match name.as_str() {
            "representation" => return Err(ProblemCode::AccessProfileInvalid),
            "accessProfile" => {}
            _ => continue,
        }
        if requested.is_some()
            || raw_value.len() > MAXIMUM_ENCODED_VALUE_BYTES
            || raw_value.contains('=')
        {
            return Err(ProblemCode::AccessProfileInvalid);
        }
        requested = Some(decode_bounded_query_component(
            raw_value,
            MAXIMUM_ENCODED_VALUE_BYTES,
        )?);
    }
    Ok(requested)
}

fn decode_bounded_query_component(
    raw: &str,
    maximum_encoded_bytes: usize,
) -> Result<String, ProblemCode> {
    if raw.len() > maximum_encoded_bytes || !valid_percent_encoding(raw.as_bytes()) {
        return Err(ProblemCode::AccessProfileInvalid);
    }
    url::form_urlencoded::parse(raw.as_bytes())
        .next()
        .map(|(value, _)| value.into_owned())
        .ok_or(ProblemCode::AccessProfileInvalid)
}

fn valid_access_profile_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn prepare_list(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access: &Access,
    query: Option<&str>,
) -> Result<PreparedList, ProblemCode> {
    let parameters = parse_query(query)?;
    let cursors = parameters
        .iter()
        .filter(|(name, _)| name == "cursor")
        .collect::<Vec<_>>();
    let pagination = operation
        .query
        .pagination
        .as_ref()
        .ok_or(ProblemCode::Internal)?;
    if !cursors.is_empty() {
        if cursors.len() != 1
            || parameters
                .iter()
                .any(|(name, _)| name != "cursor" && name != "accessProfile")
        {
            return Err(ProblemCode::CursorInvalid);
        }
        let key = service
            .cursor_key
            .as_ref()
            .ok_or(ProblemCode::CursorInvalid)?;
        let payload = decode_cursor(key, &cursors[0].1, now_unix_seconds())
            .map_err(|_| ProblemCode::CursorInvalid)?;
        if payload.page_size == 0
            || payload.page_size > pagination.maximum_page_size
            || payload.last_order_values.len() != operation.query.order_by.len()
        {
            return Err(ProblemCode::CursorInvalid);
        }
        let filters = payload
            .filters
            .iter()
            .map(|(name, value)| (name.clone(), cursor_to_sql(value.clone())))
            .collect::<BTreeMap<_, _>>();
        validate_filter_inventory(operation, &filters)?;
        validate_selected_inventory(
            resource,
            operation,
            &access.access_profile,
            &payload.selected_fields,
        )?;
        let current_source_revision = service
            .sqlite
            .source_revision(&operation.identifier)
            .ok_or(ProblemCode::CursorInvalid)?
            .cursor_value();
        let request = cursor_template(
            service,
            operation,
            access,
            &filters,
            &payload.selected_fields,
            &current_source_revision,
        )?;
        require_same_request(&payload, &request).map_err(|_| ProblemCode::CursorInvalid)?;
        return Ok(PreparedList {
            page_size: payload.page_size,
            filters,
            selected_fields: payload.selected_fields,
            after_order: Some(
                payload
                    .last_order_values
                    .into_iter()
                    .map(cursor_to_sql)
                    .collect(),
            ),
        });
    }

    let mut page_size = pagination.default_page_size;
    let mut page_size_seen = false;
    let mut fields_text = None;
    let declared = operation
        .query
        .filters
        .iter()
        .map(|filter| filter.parameter.as_str())
        .collect::<BTreeSet<_>>();
    let mut raw_filters = BTreeMap::new();
    for (name, value) in parameters {
        match name.as_str() {
            "pageSize" => {
                if page_size_seen || value.is_empty() {
                    return Err(ProblemCode::ConsultationInvalidRequest);
                }
                page_size_seen = true;
                page_size = value
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value > 0 && *value <= pagination.maximum_page_size)
                    .ok_or(ProblemCode::ConsultationInvalidRequest)?;
            }
            "fields" => {
                if fields_text.replace(value).is_some() {
                    return Err(ProblemCode::FieldsInvalid);
                }
            }
            "accessProfile" => {}
            _ if declared.contains(name.as_str()) => {
                if raw_filters.insert(name, value).is_some() {
                    return Err(ProblemCode::InvalidFilter);
                }
            }
            _ => return Err(ProblemCode::UnknownFilter),
        }
    }
    if raw_filters.is_empty() && !operation.query.allow_unfiltered {
        return Err(ProblemCode::InvalidFilter);
    }
    let mut filters = BTreeMap::new();
    for filter in &operation.query.filters {
        if let Some(value) = raw_filters.get(&filter.parameter) {
            filters.insert(
                filter.parameter.clone(),
                parse_text_value(value, filter.data_type).ok_or(ProblemCode::InvalidFilter)?,
            );
            if filter.data_type == DataType::ControlledCode {
                let property = resource
                    .properties
                    .iter()
                    .find(|property| property.name == filter.property)
                    .ok_or(ProblemCode::InvalidFilter)?;
                if !codelist_accepts(service, property.codelist.as_deref(), value) {
                    return Err(ProblemCode::InvalidFilter);
                }
            }
        }
    }
    let selected_fields = fields_from_text(
        resource,
        operation,
        &access.access_profile,
        fields_text.as_deref(),
    )?;
    Ok(PreparedList {
        page_size,
        filters,
        selected_fields,
        after_order: None,
    })
}

fn selected_fields(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
    query: Option<&str>,
) -> Result<Vec<String>, ProblemCode> {
    let parameters = parse_query(query)?;
    if parameters
        .iter()
        .any(|(name, _)| name != "fields" && name != "accessProfile")
    {
        return Err(ProblemCode::ConsultationInvalidRequest);
    }
    let fields = one_parameter(&parameters, "fields")?;
    fields_from_text(resource, operation, access_profile, fields)
}

fn fields_from_text(
    resource: &CompiledResource,
    _operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
    text: Option<&str>,
) -> Result<Vec<String>, ProblemCode> {
    let Some(text) = text else {
        return Ok(access_profile.selectable_properties.clone());
    };
    if text.is_empty() || text.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ProblemCode::FieldsInvalid);
    }
    let requested = text.split(',').collect::<Vec<_>>();
    if requested.is_empty()
        || requested.iter().any(|field| field.is_empty())
        || requested.iter().collect::<BTreeSet<_>>().len() != requested.len()
    {
        return Err(ProblemCode::FieldsInvalid);
    }
    let allowed = access_profile
        .selectable_properties
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if requested.iter().any(|field| {
        !allowed.contains(field)
            || !resource
                .properties
                .iter()
                .any(|property| property.name == **field)
    }) {
        return Err(ProblemCode::FieldsInvalid);
    }
    Ok(access_profile
        .selectable_properties
        .iter()
        .filter(|field| requested.contains(&field.as_str()))
        .cloned()
        .collect())
}

fn validate_selected_inventory(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
    fields: &[String],
) -> Result<(), ProblemCode> {
    if fields.is_empty() {
        return Err(ProblemCode::CursorInvalid);
    }
    let text = fields.join(",");
    let canonical = fields_from_text(resource, operation, access_profile, Some(&text))
        .map_err(|_| ProblemCode::CursorInvalid)?;
    if canonical != fields {
        return Err(ProblemCode::CursorInvalid);
    }
    Ok(())
}

fn validate_filter_inventory(
    operation: &CompiledOperation,
    filters: &BTreeMap<String, SqlValue>,
) -> Result<(), ProblemCode> {
    let declared = operation
        .query
        .filters
        .iter()
        .map(|filter| filter.parameter.as_str())
        .collect::<BTreeSet<_>>();
    if filters.keys().any(|name| !declared.contains(name.as_str()))
        || (filters.is_empty() && !operation.query.allow_unfiltered)
    {
        return Err(ProblemCode::CursorInvalid);
    }
    Ok(())
}

fn parse_query(query: Option<&str>) -> Result<Vec<(String, String)>, ProblemCode> {
    let Some(query) = query else {
        return Ok(Vec::new());
    };
    if query.len() > 16 * 1024 || !valid_percent_encoding(query.as_bytes()) {
        return Err(ProblemCode::ConsultationInvalidRequest);
    }
    Ok(url::form_urlencoded::parse(query.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect())
}

fn valid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%' {
            if index + 2 >= value.len()
                || !value[index + 1].is_ascii_hexdigit()
                || !value[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 2;
        }
        index += 1;
    }
    true
}

fn one_parameter<'a>(
    parameters: &'a [(String, String)],
    name: &str,
) -> Result<Option<&'a str>, ProblemCode> {
    let values = parameters
        .iter()
        .filter(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value)),
        _ => Err(if name == "fields" {
            ProblemCode::FieldsInvalid
        } else {
            ProblemCode::ConsultationInvalidRequest
        }),
    }
}

fn parse_text_value(value: &str, data_type: DataType) -> Option<SqlValue> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return None;
    }
    match data_type {
        DataType::String | DataType::ControlledCode => Some(SqlValue::String(value.to_owned())),
        DataType::Boolean => match value {
            "true" => Some(SqlValue::Boolean(true)),
            "false" => Some(SqlValue::Boolean(false)),
            _ => None,
        },
        DataType::Integer => value.parse::<i64>().ok().map(SqlValue::Integer),
        DataType::Date => NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()
            .map(|_| SqlValue::String(value.to_owned())),
        DataType::DateTime => DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|_| SqlValue::String(value.to_owned())),
        DataType::Year => (value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| SqlValue::String(value.to_owned())),
        DataType::YearMonth => valid_year_month(value).then(|| SqlValue::String(value.to_owned())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupBody {
    selectors: OrderedMap<Value>,
}

fn parse_selectors(
    service: &RelayService,
    operation: &CompiledOperation,
    bytes: &[u8],
) -> Result<BTreeMap<String, SqlValue>, ProblemCode> {
    let body: LookupBody =
        serde_json::from_slice(bytes).map_err(|_| ProblemCode::ConsultationInvalidRequest)?;
    if body.selectors.len() != operation.query.selectors.len() {
        return Err(ProblemCode::ConsultationInvalidRequest);
    }
    let mut output = BTreeMap::new();
    for selector in &operation.query.selectors {
        let value = body
            .selectors
            .get(&selector.name)
            .ok_or(ProblemCode::ConsultationInvalidRequest)?;
        let value = json_scalar_to_sql(value, selector.data_type)
            .ok_or(ProblemCode::ConsultationInvalidRequest)?;
        if selector.data_type == DataType::ControlledCode {
            let text = match &value {
                SqlValue::String(value) => value.as_str(),
                _ => return Err(ProblemCode::ConsultationInvalidRequest),
            };
            if !codelist_accepts(service, selector.codelist.as_deref(), text) {
                return Err(ProblemCode::ConsultationInvalidRequest);
            }
        }
        if let SqlValue::String(text) = &value {
            let length = text.len();
            if selector
                .minimum_bytes
                .is_some_and(|minimum| length < usize::try_from(minimum).unwrap_or(usize::MAX))
                || selector
                    .maximum_bytes
                    .is_some_and(|maximum| length > usize::try_from(maximum).unwrap_or(0))
            {
                return Err(ProblemCode::ConsultationInvalidRequest);
            }
        }
        output.insert(selector.name.clone(), value);
    }
    Ok(output)
}

fn json_scalar_to_sql(value: &Value, data_type: DataType) -> Option<SqlValue> {
    match data_type {
        DataType::String | DataType::ControlledCode => value
            .as_str()
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .map(|value| SqlValue::String(value.to_owned())),
        DataType::Boolean => value.as_bool().map(SqlValue::Boolean),
        DataType::Integer => value.as_i64().map(SqlValue::Integer),
        DataType::Date => value.as_str().and_then(|value| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()
                .map(|_| SqlValue::String(value.to_owned()))
        }),
        DataType::DateTime => value.as_str().and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|_| SqlValue::String(value.to_owned()))
        }),
        DataType::Year => value
            .as_str()
            .filter(|value| value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit()))
            .map(|value| SqlValue::String(value.to_owned())),
        DataType::YearMonth => value
            .as_str()
            .filter(|value| valid_year_month(value))
            .map(|value| SqlValue::String(value.to_owned())),
    }
}

fn valid_year_month(value: &str) -> bool {
    value.len() == 7
        && value.as_bytes().get(4) == Some(&b'-')
        && value.bytes().take(4).all(|byte| byte.is_ascii_digit())
        && matches!(
            &value[5..],
            "01" | "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12"
        )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordError {
    InvalidCore,
    InvalidSource,
}

fn record_value(
    service: &RelayService,
    resource: &CompiledResource,
    access_profile: &CompiledAccessProfile,
    row: &ResultRow,
    selected: &[String],
) -> Result<Value, RecordError> {
    let record_identifier = required_string(row, &resource.record_context.record_identifier_column)
        .ok_or(RecordError::InvalidCore)?;
    if !valid_record_identifier(record_identifier) {
        return Err(RecordError::InvalidCore);
    }
    let revision = required_string(row, &resource.record_context.revision_identifier_column)
        .ok_or(RecordError::InvalidCore)?;
    let lifecycle = required_string(row, &resource.record_context.lifecycle_state_column)
        .ok_or(RecordError::InvalidCore)?;
    let recorded_at = required_string(row, &resource.record_context.recorded_at_column)
        .ok_or(RecordError::InvalidCore)?;
    DateTime::parse_from_rfc3339(recorded_at).map_err(|_| RecordError::InvalidCore)?;
    if revision.is_empty()
        || lifecycle.is_empty()
        || !codelist_accepts(
            service,
            Some(&resource.record_context.lifecycle_state_codelist),
            lifecycle,
        )
    {
        return Err(RecordError::InvalidCore);
    }
    // Validate the complete selected access profile before requester field
    // minimization. Narrowing disclosure never lowers its processing floor.
    let properties = access_profile
        .selectable_properties
        .iter()
        .map(|name| {
            resource
                .properties
                .iter()
                .find(|property| property.name == *name)
                .ok_or(RecordError::InvalidSource)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut transformed = BTreeMap::new();
    for property in &properties {
        let source = row
            .get(&property.source_column)
            .ok_or(RecordError::InvalidSource)?;
        if matches!(source, SqlValue::Null) {
            if property.source_required {
                return Err(RecordError::InvalidSource);
            }
            continue;
        }
        let value = match &property.transform {
            Some(compiled) => {
                transform::apply(compiled, source).map_err(|_| RecordError::InvalidSource)?
            }
            None => source.clone(),
        };
        if matches!(value, SqlValue::Null) {
            if property.source_required {
                return Err(RecordError::InvalidSource);
            }
            continue;
        }
        if !valid_property_value(
            service,
            &value,
            property.data_type,
            property.codelist.as_deref(),
        ) {
            return Err(RecordError::InvalidSource);
        }
        transformed.insert(property.name.as_str(), value);
    }
    let mut domain = Map::new();
    for property in properties {
        if !selected.contains(&property.name) {
            continue;
        }
        if let Some(value) = transformed.remove(property.name.as_str()) {
            domain.insert(
                property.name.clone(),
                sql_to_json(value).ok_or(RecordError::InvalidSource)?,
            );
        }
    }
    Ok(json!({
        "registryIdentifier": service.registry.registry_identifier,
        "recordIdentifier": record_identifier,
        "revisionIdentifier": revision,
        "lifecycleState": lifecycle,
        "schemaReference": access_profile.schema_reference,
        "semanticModelReference": access_profile.semantic_model_reference,
        "authorityIdentifier": service.registry.authority_identifier,
        "recordedAt": recorded_at,
        "domainData": domain,
    }))
}

fn valid_property_value(
    service: &RelayService,
    value: &SqlValue,
    data_type: DataType,
    codelist: Option<&str>,
) -> bool {
    match (value, data_type) {
        (SqlValue::String(_), DataType::String) => true,
        (SqlValue::String(value), DataType::ControlledCode) => {
            codelist_accepts(service, codelist, value)
        }
        (SqlValue::String(value), DataType::Date) => {
            NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
        }
        (SqlValue::String(value), DataType::DateTime) => {
            DateTime::parse_from_rfc3339(value).is_ok()
        }
        (SqlValue::String(value), DataType::Year) => {
            value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit())
        }
        (SqlValue::String(value), DataType::YearMonth) => valid_year_month(value),
        (SqlValue::Boolean(_), DataType::Boolean) | (SqlValue::Integer(_), DataType::Integer) => {
            true
        }
        _ => false,
    }
}

fn codelist_accepts(service: &RelayService, path: Option<&str>, value: &str) -> bool {
    let Some(path) = path else {
        return false;
    };
    service
        .registry
        .codelists
        .iter()
        .find(|codelist| codelist.path == path)
        .is_some_and(|codelist| codelist.values.iter().any(|candidate| candidate == value))
}

fn required_string<'a>(row: &'a ResultRow, column: &str) -> Option<&'a str> {
    match row.get(column)? {
        SqlValue::String(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn sql_to_json(value: SqlValue) -> Option<Value> {
    match value {
        SqlValue::Null => Some(Value::Null),
        SqlValue::String(value) => Some(Value::String(value)),
        SqlValue::Integer(value) => Some(json!(value)),
        SqlValue::Number(value) if value.is_finite() => Some(json!(value)),
        SqlValue::Boolean(value) => Some(Value::Bool(value)),
        SqlValue::Number(_) => None,
    }
}

fn record_meta(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
    selected: &[String],
    source_revision: &SourceRevision,
) -> Value {
    let pattern = operation_pattern(&operation.kind);
    json!({
        "operationIdentifier": operation.identifier,
        "accessProfile": access_profile.id,
        "family": "consultation",
        "pattern": pattern,
        "disclosureProfile": access_profile.disclosure_profile,
        "contractRevision": service.registry.contract_revision,
        "sourceRevision": source_revision_value(source_revision),
        "selectedFields": selected,
        "links": {
            "self": operation_href(service, resource, operation),
            "context": access_profile.context_reference,
            "schema": access_profile.schema_reference,
            "semanticModel": access_profile.semantic_model_reference,
        }
    })
}

fn source_revision_value(source: &SourceRevision) -> Value {
    match source {
        SourceRevision::Snapshot(value) => {
            json!({"profile": "snapshot", "status": "versioned", "value": value})
        }
        SourceRevision::LiveUnversioned => {
            json!({"profile": "live", "status": "unversioned", "value": null})
        }
    }
}

fn apply_json_ld(
    service: &RelayService,
    resource: &CompiledResource,
    selected: &CompiledAccessProfile,
    representation: ResponseFormat,
    document: &mut Value,
) {
    if representation != ResponseFormat::JsonLd {
        return;
    }
    let context = selected.context_reference.clone();
    if let Some(object) = document.as_object_mut() {
        object.insert("@context".into(), Value::String(context));
        if let Some(data) = object.get_mut("data") {
            add_record_id(service, resource, data);
        }
        if let Some(items) = object.get_mut("items").and_then(Value::as_array_mut) {
            for item in items {
                add_record_id(service, resource, item);
            }
        }
    }
}

fn add_record_id(service: &RelayService, resource: &CompiledResource, record: &mut Value) {
    let Some(identifier) = record
        .get("recordIdentifier")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return;
    };
    if let Some(object) = record.as_object_mut() {
        object.insert(
            "@id".into(),
            Value::String(absolute(
                &service.registry.base_uri,
                &format!("/v2/resources/{}/records/{identifier}", resource.id),
            )),
        );
        object.insert(
            "@type".into(),
            Value::String(resource.semantic_class.clone()),
        );
    }
}

async fn release_document(
    service: &RelayService,
    audit: &AuditContext,
    document: Value,
    representation: ResponseFormat,
    cacheable: bool,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Response<Body> {
    let bytes = match bounded_json_bytes(&document, MAXIMUM_SERIALIZED_RESPONSE_BYTES) {
        Ok(value) => value,
        Err(_) => {
            return terminal_problem(
                &service.audit,
                audit,
                AuditOutcome::InternalFailed,
                ProblemCode::Internal,
                trace,
            )
            .await
        }
    };
    let etag = cacheable.then(|| exact_etag(&bytes));
    if etag
        .as_deref()
        .is_some_and(|tag| if_none_match(headers, tag))
    {
        if service
            .audit
            .terminal(audit, AuditOutcome::NotModified, None)
            .await
            .is_err()
        {
            return ProblemCode::AuditUnavailable.response(trace);
        }
        return not_modified(etag.as_deref().unwrap_or_default(), trace);
    }
    if service
        .audit
        .terminal(audit, AuditOutcome::Released, Some(&bytes))
        .await
        .is_err()
    {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    bytes_response(
        bytes,
        representation.media_type(),
        cacheable,
        etag.as_deref(),
        trace,
    )
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl io::Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(length) = self.bytes.len().checked_add(buffer.len()) else {
            return Err(io::Error::other("serialized response limit exceeded"));
        };
        if length > self.maximum {
            return Err(io::Error::other("serialized response limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_bytes(document: &Value, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, document).map_err(|_| ())?;
    Ok(writer.bytes)
}

async fn source_failure(
    audit: &RelayAudit,
    context: &AuditContext,
    error: SqliteRuntimeError,
    trace: &TraceContext,
) -> Response<Body> {
    let (outcome, code) = match error {
        SqliteRuntimeError::AdmissionTimeout => (AuditOutcome::TimedOut, ProblemCode::Timeout),
        SqliteRuntimeError::Source(error) if sqlite_error_is_timeout(error.kind()) => {
            (AuditOutcome::TimedOut, ProblemCode::Timeout)
        }
        SqliteRuntimeError::UnknownOperation | SqliteRuntimeError::InvalidPlan => {
            (AuditOutcome::InternalFailed, ProblemCode::Internal)
        }
        SqliteRuntimeError::MissingSource
        | SqliteRuntimeError::SchemaMismatch
        | SqliteRuntimeError::InvalidSourceShape
        | SqliteRuntimeError::Source(_) => {
            (AuditOutcome::SourceFailed, ProblemCode::SourceUnavailable)
        }
    };
    if audit.terminal(context, outcome, None).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

const fn sqlite_error_is_timeout(kind: SqliteErrorKind) -> bool {
    // `Timeout` is the platform's queue-and-async-deadline category;
    // `TimeBudgetExceeded` is the engine deadline category.
    matches!(
        kind,
        SqliteErrorKind::Timeout | SqliteErrorKind::TimeBudgetExceeded
    )
}

async fn source_shape_failure(
    audit: &RelayAudit,
    context: &AuditContext,
    trace: &TraceContext,
) -> Response<Body> {
    if audit
        .terminal(context, AuditOutcome::SourceFailed, None)
        .await
        .is_err()
    {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    ProblemCode::SourceUnavailable.response(trace)
}

async fn terminal_problem(
    audit: &RelayAudit,
    context: &AuditContext,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    if audit.terminal(context, outcome, None).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

fn cacheable(access_profile: &CompiledAccessProfile, source: &SourceRevision) -> bool {
    matches!(access_profile.access, CompiledAccess::Public)
        && access_profile.processing_handling == Handling::Public
        && matches!(source, SourceRevision::Snapshot(_))
}

fn negotiate(headers: &HeaderMap) -> Result<ResponseFormat, ProblemCode> {
    if !headers.contains_key(ACCEPT) {
        return Ok(ResponseFormat::Json);
    }

    let mut json = None;
    let mut json_ld = None;
    for value in headers.get_all(ACCEPT) {
        let value = value.to_str().map_err(|_| ProblemCode::UnsupportedFormat)?;
        for item in value.split(',') {
            let mut parts = item.trim().split(';');
            let media = parts.next().unwrap_or_default().trim();
            let Some(quality) = accept_quality(parts) else {
                continue;
            };
            if media.eq_ignore_ascii_case("application/json") {
                update_preference(&mut json, 2, quality);
            } else if media.eq_ignore_ascii_case("application/ld+json") {
                update_preference(&mut json_ld, 2, quality);
            } else if media.eq_ignore_ascii_case("application/*") {
                update_preference(&mut json, 1, quality);
                update_preference(&mut json_ld, 1, quality);
            } else if media == "*/*" {
                update_preference(&mut json, 0, quality);
                update_preference(&mut json_ld, 0, quality);
            }
        }
    }

    let json = json.map_or(0, |(_, quality)| quality);
    let json_ld = json_ld.map_or(0, |(_, quality)| quality);
    match (json, json_ld) {
        (0, 0) => Err(ProblemCode::UnsupportedFormat),
        (json, json_ld) if json_ld > json => Ok(ResponseFormat::JsonLd),
        _ => Ok(ResponseFormat::Json),
    }
}

fn update_preference(preference: &mut Option<(u8, u16)>, specificity: u8, quality: u16) {
    match preference {
        Some((current_specificity, current_quality)) if *current_specificity > specificity => {}
        Some((current_specificity, current_quality)) if *current_specificity == specificity => {
            *current_quality = (*current_quality).max(quality);
        }
        _ => *preference = Some((specificity, quality)),
    }
}

fn accept_quality<'a>(parameters: impl Iterator<Item = &'a str>) -> Option<u16> {
    let mut quality = None;
    for parameter in parameters {
        let parameter = parameter.trim();
        let Some((name, value)) = parameter.split_once('=') else {
            if parameter.eq_ignore_ascii_case("q") {
                return None;
            }
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            if quality.is_some() {
                return None;
            }
            quality = Some(parse_quality(value.trim())?);
        }
    }
    Some(quality.unwrap_or(1_000))
}

fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let parsed = if fraction.is_empty() {
                0
            } else {
                fraction.parse::<u16>().ok()?
            };
            Some(parsed * 10_u16.pow(u32::try_from(3_usize.saturating_sub(fraction.len())).ok()?))
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1_000),
        _ => None,
    }
}

fn rejects_caller_purpose(headers: &HeaderMap) -> bool {
    headers.contains_key("purpose") || headers.contains_key("x-purpose")
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn next_cursor(
    service: &RelayService,
    operation: &CompiledOperation,
    access: &Access,
    query: &PreparedList,
    last: &ResultRow,
    source_revision: &SourceRevision,
) -> Result<String, ()> {
    let key = service.cursor_key.as_ref().ok_or(())?;
    let last_record_identifier = operation
        .query
        .order_by
        .last()
        .and_then(|column| last.get(column))
        .and_then(|value| match value {
            SqlValue::String(value) => Some(value.clone()),
            _ => None,
        })
        .ok_or(())?;
    let last_order_values = operation
        .query
        .order_by
        .iter()
        .map(|column| last.get(column).cloned().and_then(sql_to_cursor).ok_or(()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut payload = cursor_template(
        service,
        operation,
        access,
        &query.filters,
        &query.selected_fields,
        &source_revision.cursor_value(),
    )
    .map_err(|_| ())?;
    payload.expires_at_unix_seconds = now_unix_seconds()
        .checked_add(service.cursor_maximum_age.as_secs())
        .ok_or(())?;
    payload.last_record_identifier = last_record_identifier;
    payload.page_size = query.page_size;
    payload.filters = query
        .filters
        .iter()
        .map(|(name, value)| Ok((name.clone(), sql_to_cursor(value.clone()).ok_or(())?)))
        .collect::<Result<_, ()>>()?;
    payload.selected_fields = query.selected_fields.clone();
    payload.last_order_values = last_order_values;
    encode_cursor(key, &payload).map_err(|_| ())
}

fn cursor_order_values(order_by: &[String], row: &ResultRow) -> Option<Vec<CursorValue>> {
    order_by
        .iter()
        .map(|column| row.get(column).cloned().and_then(sql_to_cursor))
        .collect()
}

fn cursor_template(
    service: &RelayService,
    operation: &CompiledOperation,
    access: &Access,
    filters: &BTreeMap<String, SqlValue>,
    selected_fields: &[String],
    source_revision: &str,
) -> Result<CursorPayload, ProblemCode> {
    let key = service
        .cursor_key
        .as_ref()
        .ok_or(ProblemCode::CursorInvalid)?;
    let filter_json = serde_json::to_vec(filters).map_err(|_| ProblemCode::CursorInvalid)?;
    let field_json = serde_json::to_vec(selected_fields).map_err(|_| ProblemCode::CursorInvalid)?;
    let order_json =
        serde_json::to_vec(&operation.query.order_by).map_err(|_| ProblemCode::CursorInvalid)?;
    let transform_json = serde_json::to_vec(&access.access_profile.transform_inventory)
        .map_err(|_| ProblemCode::CursorInvalid)?;
    let authorization_material = access
        .principal
        .as_ref()
        .map(|principal| {
            principal.authorization_material(&access.access_profile.access, &access.authorization)
        })
        .unwrap_or_else(|| b"anonymous".to_vec());
    Ok(CursorPayload::new(
        u64::MAX,
        service.registry.contract_revision.clone(),
        source_revision.to_owned(),
        operation.identifier.clone(),
        CursorBindings {
            access_profile: access.access_profile.id.clone(),
            disclosure_profile: access.access_profile.disclosure_profile.clone(),
            transforms_digest: key
                .binding_digest(b"transforms", &transform_json)
                .map_err(|_| ProblemCode::CursorInvalid)?,
            filters_digest: key
                .binding_digest(b"filters", &filter_json)
                .map_err(|_| ProblemCode::CursorInvalid)?,
            selected_fields_digest: key
                .binding_digest(b"fields", &field_json)
                .map_err(|_| ProblemCode::CursorInvalid)?,
            authorization_digest: key
                .binding_digest(b"authorization", &authorization_material)
                .map_err(|_| ProblemCode::CursorInvalid)?,
            order_digest: key
                .binding_digest(b"order", &order_json)
                .map_err(|_| ProblemCode::CursorInvalid)?,
            last_record_identifier: String::new(),
        },
    ))
}

fn metadata_cursor_template(
    service: &RelayService,
    visible: &[(&CompiledResource, Vec<VisibleAccessProfile<'_>>)],
) -> Result<CursorPayload, ProblemCode> {
    let key = service
        .cursor_key
        .as_ref()
        .ok_or(ProblemCode::CursorInvalid)?;
    let authorization_material = visible
        .iter()
        .map(|(resource, operations)| {
            (
                resource.id.as_str(),
                operations
                    .iter()
                    .map(|(operation, access_profile)| {
                        (operation.identifier.as_str(), access_profile.id.as_str())
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let authorization_material =
        serde_json::to_vec(&authorization_material).map_err(|_| ProblemCode::CursorInvalid)?;
    Ok(CursorPayload::new(
        u64::MAX,
        service.registry.contract_revision.clone(),
        format!("metadata:{}", service.registry.contract_revision),
        "registry.resources".to_owned(),
        CursorBindings {
            access_profile: "metadata".to_owned(),
            disclosure_profile: "metadata".to_owned(),
            transforms_digest: key
                .binding_digest(b"metadata-transforms", b"none")
                .map_err(|_| ProblemCode::CursorInvalid)?,
            filters_digest: key
                .binding_digest(b"metadata-filters", b"none")
                .map_err(|_| ProblemCode::CursorInvalid)?,
            selected_fields_digest: key
                .binding_digest(b"metadata-fields", b"fixed")
                .map_err(|_| ProblemCode::CursorInvalid)?,
            authorization_digest: key
                .binding_digest(b"metadata-authorization", &authorization_material)
                .map_err(|_| ProblemCode::CursorInvalid)?,
            order_digest: key
                .binding_digest(b"metadata-order", b"resourceIdentifier")
                .map_err(|_| ProblemCode::CursorInvalid)?,
            last_record_identifier: String::new(),
        },
    ))
}

fn metadata_next_cursor(
    service: &RelayService,
    visible: &[(&CompiledResource, Vec<VisibleAccessProfile<'_>>)],
    page_size: usize,
    last_resource_identifier: &str,
) -> Result<String, ProblemCode> {
    let key = service
        .cursor_key
        .as_ref()
        .ok_or(ProblemCode::CursorInvalid)?;
    let mut payload = metadata_cursor_template(service, visible)?;
    payload.expires_at_unix_seconds = now_unix_seconds()
        .checked_add(service.cursor_maximum_age.as_secs())
        .ok_or(ProblemCode::CursorInvalid)?;
    payload.page_size = u32::try_from(page_size).map_err(|_| ProblemCode::CursorInvalid)?;
    payload.last_record_identifier = last_resource_identifier.to_owned();
    encode_cursor(key, &payload).map_err(|_| ProblemCode::CursorInvalid)
}

fn sql_to_cursor(value: SqlValue) -> Option<CursorValue> {
    match value {
        SqlValue::String(value) => Some(CursorValue::String(value)),
        SqlValue::Integer(value) => Some(CursorValue::Integer(value)),
        SqlValue::Boolean(value) => Some(CursorValue::Boolean(value)),
        SqlValue::Null | SqlValue::Number(_) => None,
    }
}

fn cursor_to_sql(value: CursorValue) -> SqlValue {
    match value {
        CursorValue::String(value) => SqlValue::String(value),
        CursorValue::Integer(value) => SqlValue::Integer(value),
        CursorValue::Boolean(value) => SqlValue::Boolean(value),
    }
}

fn find_operation<'a>(
    service: &'a RelayService,
    resource_id: &str,
    predicate: impl Fn(&OperationKind) -> bool,
) -> Option<(&'a CompiledResource, &'a CompiledOperation)> {
    let resource = service
        .registry
        .resources
        .iter()
        .find(|resource| resource.id == resource_id)?;
    let operation = resource
        .operations
        .iter()
        .find(|operation| predicate(&operation.kind))?;
    Some((resource, operation))
}

fn find_operation_by_id<'a>(
    service: &'a RelayService,
    identifier: &str,
) -> Option<&'a CompiledOperation> {
    service
        .registry
        .resources
        .iter()
        .flat_map(|resource| resource.operations.iter())
        .find(|operation| operation.identifier == identifier)
}

async fn visible_resources<'a>(
    service: &'a RelayService,
    principal: Option<&Principal>,
) -> Result<Vec<(&'a CompiledResource, Vec<VisibleAccessProfile<'a>>)>, ProblemCode> {
    if service.registry.metadata_visibility.resources == Visibility::OperatorOnly {
        return Err(ProblemCode::ResourceNotFound);
    }
    if service.registry.metadata_visibility.resources == Visibility::OperationBound
        && principal.is_none()
    {
        return Err(ProblemCode::MissingCredential);
    }
    let mut visible = Vec::new();
    for resource in &service.registry.resources {
        let operations = visible_operations(service, resource, principal).await?;
        if !operations.is_empty() {
            visible.push((resource, operations));
        }
    }
    Ok(visible)
}

async fn visible_operations<'a>(
    service: &'a RelayService,
    resource: &'a CompiledResource,
    principal: Option<&Principal>,
) -> Result<Vec<VisibleAccessProfile<'a>>, ProblemCode> {
    match service.registry.metadata_visibility.resources {
        Visibility::OperatorOnly => Ok(Vec::new()),
        Visibility::Public => Ok(resource
            .operations
            .iter()
            .flat_map(|operation| {
                operation
                    .access_profiles
                    .iter()
                    .filter(|access_profile| {
                        matches!(access_profile.access, CompiledAccess::Public)
                    })
                    .map(move |access_profile| (operation, access_profile))
            })
            .collect()),
        Visibility::OperationBound => {
            let principal = principal.ok_or(ProblemCode::MissingCredential)?;
            let authenticator = service
                .authenticator
                .as_ref()
                .ok_or(ProblemCode::ResourceNotFound)?;
            Ok(resource
                .operations
                .iter()
                .flat_map(|operation| {
                    operation
                        .access_profiles
                        .iter()
                        .filter_map(move |access_profile| {
                            authenticator
                                .authorize(&access_profile.access, Some(principal))
                                .is_ok()
                                .then_some((operation, access_profile))
                        })
                })
                .collect())
        }
    }
}

fn protected_metadata_exists(service: &RelayService) -> bool {
    service.registry.metadata_visibility.resources == Visibility::OperationBound
}

fn protected_artifact(artifact: &GeneratedArtifact) -> bool {
    artifact.visibility == Visibility::OperationBound
}

type VisibleAccessProfile<'a> = (&'a CompiledOperation, &'a CompiledAccessProfile);

fn resource_document(
    service: &RelayService,
    resource: &CompiledResource,
    operations: &[VisibleAccessProfile<'_>],
) -> Value {
    let enumeration = if operations
        .iter()
        .any(|(operation, _)| matches!(operation.kind, OperationKind::List))
    {
        if operations.iter().any(|(operation, access_profile)| {
            matches!(operation.kind, OperationKind::List)
                && matches!(access_profile.access, CompiledAccess::Public)
        }) {
            "public"
        } else {
            "protected"
        }
    } else {
        "none"
    };
    json!({
        "resourceIdentifier": resource.id,
        "title": resource.title,
        "description": resource.description,
        "semanticClass": resource.semantic_class,
        "enumerationPosture": enumeration,
        "capabilities": operations.iter().map(|(operation, access_profile)| capability(service, resource, operation, access_profile)).collect::<Vec<_>>(),
        "links": {
            "self": absolute(&service.registry.base_uri, &format!("/v2/resources/{}", resource.id)),
        }
    })
}

fn capability(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    access_profile: &CompiledAccessProfile,
) -> Value {
    let mut document = json!({
        "family": "consultation",
        "pattern": operation_pattern(&operation.kind),
        "resourceIdentifier": resource.id,
        "operationIdentifier": operation.identifier,
        "accessProfileIdentifier": access_profile.id,
        "isDefault": operation.default_access_profile == access_profile.id,
        "disclosureProfile": access_profile.disclosure_profile,
        "schemaReference": access_profile.schema_reference,
        "semanticModelReference": access_profile.semantic_model_reference,
        "contextReference": access_profile.context_reference,
        "wireFormats": [
            {"id": "json", "mediaType": "application/json", "formatProfiles": []},
            {"id": "json-ld", "mediaType": "application/ld+json", "formatProfiles": []},
        ],
        "href": match &operation.kind {
            OperationKind::List => format!("/v2/resources/{}/records", resource.id),
            OperationKind::Read => format!("/v2/resources/{}/records/{{recordIdentifier}}", resource.id),
            OperationKind::Lookup {name} => format!("/v2/resources/{}/lookups/{name}", resource.id),
        }
    });
    let stem = format!(
        "{}--access-profile-{}",
        operation_artifact_stem(&resource.id, &operation.kind),
        access_profile.id
    );
    let object = document
        .as_object_mut()
        .expect("capability document is an object");
    if service.registry.metadata_visibility.classifications != Visibility::OperatorOnly {
        object.insert(
            "classificationReference".into(),
            Value::String(sibling_artifact_reference(
                &access_profile.schema_reference,
                &format!("{stem}-classifications"),
            )),
        );
    }
    if service.registry.metadata_visibility.processing != Visibility::OperatorOnly {
        object.insert(
            "processingReference".into(),
            Value::String(sibling_artifact_reference(
                &access_profile.schema_reference,
                &format!("{stem}-processing"),
            )),
        );
    }
    document
}

fn sibling_artifact_reference(reference: &str, artifact_identifier: &str) -> String {
    reference.rsplit_once("/v2/artifacts/").map_or_else(
        || format!("/v2/artifacts/{artifact_identifier}"),
        |(origin, _)| format!("{origin}/v2/artifacts/{artifact_identifier}"),
    )
}

fn operation_artifact_stem(resource: &str, kind: &OperationKind) -> String {
    match kind {
        OperationKind::List => format!("{resource}--list"),
        OperationKind::Read => format!("{resource}--read"),
        OperationKind::Lookup { name } => format!("{resource}--lookup-{name}"),
    }
}

fn operation_pattern(kind: &OperationKind) -> &'static str {
    match kind {
        OperationKind::List => "list",
        OperationKind::Read => "retrieve",
        OperationKind::Lookup { .. } => "search",
    }
}

fn operation_href(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
) -> String {
    let path = match &operation.kind {
        OperationKind::List => format!("/v2/resources/{}/records", resource.id),
        OperationKind::Read => {
            format!("/v2/resources/{}/records/{{recordIdentifier}}", resource.id)
        }
        OperationKind::Lookup { name } => {
            format!("/v2/resources/{}/lookups/{name}", resource.id)
        }
    };
    absolute(&service.registry.base_uri, &path)
}

fn absolute(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{base}{path}")
}

fn valid_record_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn minimal_status(status: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(format!("{{\"status\":\"{status}\"}}")));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn json_metadata_response(
    value: Value,
    cacheable: bool,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Response<Body> {
    let bytes = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    static_bytes_response(&bytes, "application/json", cacheable, headers, trace)
}

fn static_bytes_response(
    bytes: &[u8],
    media_type: &str,
    cacheable: bool,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Response<Body> {
    let etag = cacheable.then(|| exact_etag(bytes));
    if etag
        .as_deref()
        .is_some_and(|value| if_none_match(headers, value))
    {
        return not_modified(etag.as_deref().unwrap_or_default(), trace);
    }
    bytes_response(
        bytes.to_vec(),
        media_type,
        cacheable,
        etag.as_deref(),
        trace,
    )
}

fn bytes_response(
    bytes: Vec<u8>,
    media_type: &str,
    cacheable: bool,
    etag: Option<&str>,
    trace: &TraceContext,
) -> Response<Body> {
    let mut response = Response::new(Body::from(bytes));
    if let Ok(content_type) = HeaderValue::from_str(media_type) {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    if cacheable {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("public, no-cache"));
        response
            .headers_mut()
            .insert(VARY, HeaderValue::from_static("Accept, Authorization"));
        if let Some(etag) = etag.and_then(|value| HeaderValue::from_str(value).ok()) {
            response.headers_mut().insert(ETAG, etag);
        }
    } else {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    trace.apply(response.headers_mut());
    response
}

fn not_modified(etag: &str, trace: &TraceContext) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("public, no-cache"));
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept, Authorization"));
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(ETAG, value);
    }
    trace.apply(response.headers_mut());
    response
}

fn exact_etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::digest(bytes)))
}

fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    let Some(current) = weak_entity_tag(etag) else {
        return false;
    };
    headers
        .get_all(IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| candidate == "*" || weak_entity_tag(candidate) == Some(current))
}

fn weak_entity_tag(value: &str) -> Option<&str> {
    let value = value.trim();
    let value = value.strip_prefix("W/").unwrap_or(value);
    (value.len() >= 2 && value.starts_with('"') && value.ends_with('"')).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(name: http::header::HeaderName, values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name.clone(), value.parse().expect("valid test header"));
        }
        headers
    }

    #[test]
    fn accept_negotiation_obeys_quality_specificity_case_and_ows() {
        assert_eq!(negotiate(&HeaderMap::new()), Ok(ResponseFormat::Json));
        assert_eq!(
            negotiate(&headers(
                ACCEPT,
                &["Application/LD+JSON ; Q = 0.5, application/json; q=0.4"]
            )),
            Ok(ResponseFormat::JsonLd)
        );
        assert_eq!(
            negotiate(&headers(
                ACCEPT,
                &["application/ld+json;q=0.000", "application/json;q=0.50"]
            )),
            Ok(ResponseFormat::Json)
        );
        assert_eq!(
            negotiate(&headers(
                ACCEPT,
                &["application/json;q=0, */*;q=0.9, application/ld+json;q=0.5"]
            )),
            Ok(ResponseFormat::JsonLd)
        );
        assert_eq!(
            negotiate(&headers(
                ACCEPT,
                &["application/ld+json;q=0.5, application/json;q=0.500"]
            )),
            Ok(ResponseFormat::Json)
        );
        for zero in ["0", "0.", "0.0", "0.00", "0.000"] {
            let value = format!("application/json;q={zero}");
            assert_eq!(
                negotiate(&headers(ACCEPT, &[&value])),
                Err(ProblemCode::UnsupportedFormat)
            );
        }
        for malformed in ["q", "q=", "q=.5", "q=1.1", "q=0.0000", "q=0.5;q=0.4"] {
            let value = format!("application/json;{malformed}");
            assert_eq!(
                negotiate(&headers(ACCEPT, &[&value])),
                Err(ProblemCode::UnsupportedFormat)
            );
        }
    }

    #[test]
    fn if_none_match_uses_weak_comparison_across_every_field_value() {
        let etag = "\"current\"";
        assert!(if_none_match(&headers(IF_NONE_MATCH, &["*"]), etag));
        assert!(if_none_match(
            &headers(IF_NONE_MATCH, &["W/\"current\""]),
            etag
        ));
        assert!(if_none_match(
            &headers(IF_NONE_MATCH, &["\"other\"", "W/\"absent\", \"current\""]),
            etag
        ));
        assert!(!if_none_match(
            &headers(IF_NONE_MATCH, &["\"other\", W/\"absent\""]),
            etag
        ));
    }

    #[test]
    fn only_platform_time_and_deadline_categories_map_to_timeout() {
        assert!(sqlite_error_is_timeout(SqliteErrorKind::Timeout));
        assert!(sqlite_error_is_timeout(SqliteErrorKind::TimeBudgetExceeded));
        assert!(!sqlite_error_is_timeout(
            SqliteErrorKind::StepBudgetExceeded
        ));
        assert!(!sqlite_error_is_timeout(SqliteErrorKind::Concurrency));
        assert!(!sqlite_error_is_timeout(SqliteErrorKind::ExecutionFailed));
    }

    #[test]
    fn cursor_order_values_must_be_present_non_null_supported_scalars() {
        let order = vec!["rank".to_owned(), "record_id".to_owned()];
        let valid = BTreeMap::from([
            ("rank".to_owned(), SqlValue::Integer(7)),
            (
                "record_id".to_owned(),
                SqlValue::String("record-7".to_owned()),
            ),
        ]);
        assert!(cursor_order_values(&order, &valid).is_some());

        let mut null = valid.clone();
        null.insert("rank".to_owned(), SqlValue::Null);
        assert!(cursor_order_values(&order, &null).is_none());

        let mut unsupported = valid;
        unsupported.insert("rank".to_owned(), SqlValue::Number(7.5));
        assert!(cursor_order_values(&order, &unsupported).is_none());
    }

    #[test]
    fn serialized_response_ceiling_counts_exact_json_bytes() {
        let document = json!({"escaped": "\n\n\n\n"});
        let expected = serde_json::to_vec(&document).expect("JSON serializes");

        assert_eq!(
            bounded_json_bytes(&document, expected.len()).expect("exact bound is accepted"),
            expected
        );
        assert!(bounded_json_bytes(&document, expected.len().saturating_sub(1)).is_err());
    }

    #[test]
    fn access_profile_selection_scans_only_bounded_components() {
        let padding = "x".repeat(20_000);
        let query = format!("padding={padding}&accessProfile=caseworker");
        assert_eq!(
            access_profile_parameter(Some(&query)).expect("selector extracts"),
            Some("caseworker".into())
        );
        assert_eq!(
            access_profile_parameter(Some("%61ccessProfile=limited"))
                .expect("encoded selector extracts"),
            Some("limited".into())
        );
        assert_eq!(
            access_profile_parameter(Some("%=ignored&accessProfile=limited"))
                .expect("malformed unrelated name is deferred"),
            Some("limited".into())
        );
        assert_eq!(
            access_profile_parameter(Some("accessProfile=limited&accessProfile=caseworker")),
            Err(ProblemCode::AccessProfileInvalid)
        );
        assert_eq!(
            access_profile_parameter(Some("accessProfile=limited=caseworker")),
            Err(ProblemCode::AccessProfileInvalid)
        );
        assert_eq!(
            access_profile_parameter(Some("representation=legacy")),
            Err(ProblemCode::AccessProfileInvalid)
        );
        assert_eq!(
            access_profile_parameter(Some("%72%65%70%72%65%73%65%6e%74%61%74%69%6f%6e=legacy")),
            Err(ProblemCode::AccessProfileInvalid)
        );
    }
}

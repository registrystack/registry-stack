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
use registry_platform_sqlite::{ResultRow, Value as SqlValue};
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
    CompiledAccess, CompiledOperation, CompiledResource, OperationKind, RowAuthoritySource,
};
use crate::problem::{ProblemCode, TraceContext};
use crate::server::{uri_within_bound, RelayService};
use crate::sqlite_runtime::{OperationQuery, SourceRevision, SqliteRuntimeError};

const PRODUCT_NAME: &str = "Registry Relay";
const PRODUCT_VERSION: &str = "2";
const API_BINDING_NAME: &str = "registry-relay-http";
const API_BINDING_VERSION: &str = "v2";
const METADATA_DEFAULT_PAGE_SIZE: usize = 50;
const METADATA_MAXIMUM_PAGE_SIZE: usize = 100;
const MAXIMUM_SERIALIZED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Representation {
    Json,
    JsonLd,
}

impl Representation {
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
            let operations = match service.registry.metadata_visibility.resources {
                Visibility::Public => resource
                    .operations
                    .iter()
                    .filter(|operation| matches!(operation.access, CompiledAccess::Public))
                    .collect::<Vec<_>>(),
                Visibility::OperationBound => match principal.as_ref() {
                    Some(principal) => {
                        match visible_operations(&service, resource, Some(principal)).await {
                            Ok(value) => value,
                            Err(code) => return code.response(&trace),
                        }
                    }
                    None => Vec::new(),
                },
                Visibility::OperatorOnly => Vec::new(),
            };
            capabilities.extend(
                operations
                    .into_iter()
                    .map(|operation| capability(&service, resource, operation)),
            );
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
            let Some(authenticator) = &service.authenticator else {
                return ProblemCode::ResourceNotFound.response(&trace);
            };
            if authenticator
                .authorize(&operation.access, Some(principal))
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
    let Some((resource, operation)) = find_operation(&service, &resource_id, |kind| {
        matches!(kind, OperationKind::List)
    }) else {
        return unknown_data_route(&service, &headers, &trace, OperationClass::List).await;
    };
    if !uri_within_bound(&uri) {
        return refuse_known(
            &service,
            resource,
            operation,
            None,
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    let access = match access_operation(&service, resource, operation, &headers, &trace).await {
        Ok(value) => value,
        Err(response) => return response,
    };
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
    let representation = match negotiate(&headers) {
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
        &access,
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
    let has_next = rows.len() > usize::try_from(query.page_size).unwrap_or(usize::MAX);
    if has_next {
        rows.pop();
    }
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let record = match record_value(&service, resource, operation, row, &query.selected_fields)
        {
            Some(value) => value,
            None => {
                if service
                    .audit
                    .terminal(&audit, AuditOutcome::InternalFailed, None)
                    .await
                    .is_err()
                {
                    return ProblemCode::AuditUnavailable.response(&trace);
                }
                return ProblemCode::Internal.response(&trace);
            }
        };
        items.push(record);
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
            Err(_) => {
                return terminal_problem(
                    &service.audit,
                    &audit,
                    AuditOutcome::InternalFailed,
                    ProblemCode::Internal,
                    &trace,
                )
                .await
            }
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
            &query.selected_fields,
            &result.source_revision,
        ),
    });
    apply_json_ld(&service, resource, operation, representation, &mut document);
    release_document(
        &service,
        &audit,
        document,
        representation,
        cacheable(operation, &result.source_revision),
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
    let Some((resource, operation)) = find_operation(&service, &resource_id, |kind| {
        matches!(kind, OperationKind::Read)
    }) else {
        return unknown_data_route(&service, &headers, &trace, OperationClass::Read).await;
    };
    let access = match access_operation(&service, resource, operation, &headers, &trace).await {
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
    let Some((resource, operation)) = find_operation(
        &service,
        &resource_id,
        |kind| matches!(kind, OperationKind::Lookup { name } if name == &lookup_id),
    ) else {
        return unknown_data_route(&service, request.headers(), &trace, OperationClass::Lookup)
            .await;
    };
    let access =
        match access_operation(&service, resource, operation, request.headers(), &trace).await {
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
    let representation = match negotiate(request.headers()) {
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
    let fields = match selected_fields(resource, operation, request.uri().query()) {
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
            prevalidated: Some((representation, fields)),
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
    prevalidated: Option<(Representation, Vec<String>)>,
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
            let fields = match selected_fields(resource, operation, request.query_text) {
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
    let audit = audit_context(service, resource, operation, &access, fields.clone(), trace);
    if service.audit.attempt(&audit).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    request.query.row_authority = access.authorization.row_authority.clone();
    let result = service
        .sqlite
        .execute(&operation.identifier, request.query)
        .await;
    let result = match result {
        Ok(value) => value,
        Err(error) => return source_failure(&service.audit, &audit, error, trace).await,
    };
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
    let Some(record) = record_value(service, resource, operation, &result.rows[0], &fields) else {
        if service
            .audit
            .terminal(&audit, AuditOutcome::Unresolved, None)
            .await
            .is_err()
        {
            return ProblemCode::AuditUnavailable.response(trace);
        }
        return ProblemCode::ConsultationUnresolved.response(trace);
    };
    let mut document = json!({
        "data": record,
        "meta": record_meta(service, resource, operation, &fields, &result.source_revision),
    });
    apply_json_ld(service, resource, operation, representation, &mut document);
    release_document(
        service,
        &audit,
        document,
        representation,
        cacheable(operation, &result.source_revision),
        headers,
        trace,
    )
    .await
}

async fn access_operation(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Result<Access, Response<Body>> {
    let principal = match optional_principal(service, headers).await {
        Ok(value) => value,
        Err(code) => {
            return Err(refuse_known(
                service,
                resource,
                operation,
                None,
                AuditOutcome::InvalidCredential,
                code,
                trace,
            )
            .await)
        }
    };
    let authorization = match &service.authenticator {
        Some(authenticator) => authenticator.authorize(&operation.access, principal.as_ref()),
        None => match operation.access {
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
        }),
        Err(error) => {
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
    headers: &HeaderMap,
    trace: &TraceContext,
    class: OperationClass,
) -> Response<Body> {
    let principal = match optional_principal(service, headers).await {
        Ok(value) => value,
        Err(code) => {
            let audit = unknown_audit_context(service, trace, PrincipalKind::Unknown);
            if service
                .audit
                .refusal(&audit, AuditOutcome::InvalidCredential)
                .await
                .is_err()
            {
                return ProblemCode::AuditUnavailable.response(trace);
            }
            return code.response(trace);
        }
    };
    let protected = service.registry.resources.iter().any(|resource| {
        resource.operations.iter().any(|operation| {
            class_matches(&operation.kind, class)
                && matches!(operation.access, CompiledAccess::Protected { .. })
        })
    });
    if protected && principal.is_none() {
        let audit = unknown_audit_context(service, trace, PrincipalKind::Unknown);
        if service
            .audit
            .refusal(&audit, AuditOutcome::MissingCredential)
            .await
            .is_err()
        {
            return ProblemCode::AuditUnavailable.response(trace);
        }
        return ProblemCode::MissingCredential.response(trace);
    }
    let audit = unknown_audit_context(
        service,
        trace,
        if principal.is_some() {
            PrincipalKind::Authenticated
        } else {
            PrincipalKind::Anonymous
        },
    );
    if service
        .audit
        .refusal(&audit, AuditOutcome::NotFound)
        .await
        .is_err()
    {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    ProblemCode::ResourceNotFound.response(trace)
}

fn class_matches(kind: &OperationKind, class: OperationClass) -> bool {
    matches!(
        (kind, class),
        (OperationKind::List, OperationClass::List)
            | (OperationKind::Read, OperationClass::Read)
            | (OperationKind::Lookup { .. }, OperationClass::Lookup)
    )
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
    let access = access.cloned().unwrap_or(Access {
        principal: None,
        authorization: Authorization {
            row_authority: None,
            purpose: None,
        },
    });
    let context = audit_context(service, resource, operation, &access, Vec::new(), trace);
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
    let context = audit_context(service, resource, operation, access, fields.to_vec(), trace);
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
    access: &Access,
    selected_properties: Vec<String>,
    trace: &TraceContext,
) -> AuditContext {
    AuditContext {
        operation_id: RelayAudit::operation_id(),
        trace_id: trace.trace_id.clone(),
        registry_identifier: service.registry.registry_identifier.clone(),
        resource_identifier: Some(resource.id.clone()),
        operation_identifier: Some(operation.identifier.clone()),
        access_rule_revision: access_revision(operation),
        purpose: access.authorization.purpose.clone(),
        row_boundary_kind: row_boundary(operation),
        disclosure_profile: Some(operation.disclosure_profile.clone()),
        processing_description_identifiers: processing_description_identifiers(resource, operation),
        selected_properties,
        maximum_handling: Some(handling_label(operation.maximum_handling).into()),
        contract_revision: service.registry.contract_revision.clone(),
        source_revision: service
            .sqlite
            .source_revision(&operation.identifier)
            .cloned(),
        principal_kind: if access.principal.is_some() {
            PrincipalKind::Authenticated
        } else {
            PrincipalKind::Anonymous
        },
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
        disclosure_profile: None,
        processing_description_identifiers: Vec::new(),
        selected_properties: Vec::new(),
        maximum_handling: None,
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

fn access_revision(operation: &CompiledOperation) -> Option<String> {
    let value = serde_json::to_value(&operation.access).ok()?;
    let bytes = canonicalize_json(&value).ok()?;
    Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn row_boundary(operation: &CompiledOperation) -> RowBoundaryKind {
    match &operation.access {
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
        if cursors.len() != 1 || parameters.len() != 1 {
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
        validate_selected_inventory(resource, operation, &payload.selected_fields)?;
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
    let selected_fields = fields_from_text(resource, operation, fields_text.as_deref())?;
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
    query: Option<&str>,
) -> Result<Vec<String>, ProblemCode> {
    let parameters = parse_query(query)?;
    if parameters.iter().any(|(name, _)| name != "fields") {
        return Err(ProblemCode::ConsultationInvalidRequest);
    }
    let fields = one_parameter(&parameters, "fields")?;
    fields_from_text(resource, operation, fields)
}

fn fields_from_text(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    text: Option<&str>,
) -> Result<Vec<String>, ProblemCode> {
    let Some(text) = text else {
        return Ok(operation.selectable_properties.clone());
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
    let allowed = operation
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
    Ok(operation
        .selectable_properties
        .iter()
        .filter(|field| requested.contains(&field.as_str()))
        .cloned()
        .collect())
}

fn validate_selected_inventory(
    resource: &CompiledResource,
    operation: &CompiledOperation,
    fields: &[String],
) -> Result<(), ProblemCode> {
    if fields.is_empty() {
        return Err(ProblemCode::CursorInvalid);
    }
    let text = fields.join(",");
    let canonical = fields_from_text(resource, operation, Some(&text))?;
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
    }
}

fn record_value(
    service: &RelayService,
    resource: &CompiledResource,
    _operation: &CompiledOperation,
    row: &ResultRow,
    selected: &[String],
) -> Option<Value> {
    let record_identifier =
        required_string(row, &resource.record_context.record_identifier_column)?;
    if !valid_record_identifier(record_identifier) {
        return None;
    }
    let revision = required_string(row, &resource.record_context.revision_identifier_column)?;
    let lifecycle = required_string(row, &resource.record_context.lifecycle_state_column)?;
    let recorded_at = required_string(row, &resource.record_context.recorded_at_column)?;
    DateTime::parse_from_rfc3339(recorded_at).ok()?;
    if revision.is_empty()
        || lifecycle.is_empty()
        || !codelist_accepts(
            service,
            Some(&resource.record_context.lifecycle_state_codelist),
            lifecycle,
        )
    {
        return None;
    }
    // Validate the complete reviewed source projection before narrowing.
    for property in &resource.properties {
        let value = row.get(&property.source_column)?;
        if matches!(value, SqlValue::Null) {
            if property.source_required {
                return None;
            }
            continue;
        }
        if !valid_property_value(
            service,
            value,
            property.data_type,
            property.codelist.as_deref(),
        ) {
            return None;
        }
    }
    let mut domain = Map::new();
    for property in &resource.properties {
        if !selected.contains(&property.name) {
            continue;
        }
        let value = row.get(&property.source_column)?;
        if !matches!(value, SqlValue::Null) {
            domain.insert(property.name.clone(), sql_to_json(value.clone())?);
        }
    }
    Some(json!({
        "registryIdentifier": service.registry.registry_identifier,
        "recordIdentifier": record_identifier,
        "revisionIdentifier": revision,
        "lifecycleState": lifecycle,
        "schemaReference": _operation.schema_reference,
        "semanticModelReference": _operation.semantic_model_reference,
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
    selected: &[String],
    source_revision: &SourceRevision,
) -> Value {
    let pattern = operation_pattern(&operation.kind);
    json!({
        "operationIdentifier": operation.identifier,
        "family": "consultation",
        "pattern": pattern,
        "disclosureProfile": operation.disclosure_profile,
        "contractRevision": service.registry.contract_revision,
        "sourceRevision": source_revision_value(source_revision),
        "selectedFields": selected,
        "links": {
            "self": operation_href(service, resource, operation),
            "context": operation.context_reference,
            "schema": operation.schema_reference,
            "semanticModel": operation.semantic_model_reference,
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
    operation: &CompiledOperation,
    representation: Representation,
    document: &mut Value,
) {
    if representation != Representation::JsonLd {
        return;
    }
    let context = operation.context_reference.clone();
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
    }
}

async fn release_document(
    service: &RelayService,
    audit: &AuditContext,
    document: Value,
    representation: Representation,
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
        SqliteRuntimeError::MissingSource
        | SqliteRuntimeError::UnknownOperation
        | SqliteRuntimeError::SchemaMismatch
        | SqliteRuntimeError::InvalidPlan => (AuditOutcome::InternalFailed, ProblemCode::Internal),
        SqliteRuntimeError::Source(_) => {
            (AuditOutcome::SourceFailed, ProblemCode::SourceUnavailable)
        }
    };
    if audit.terminal(context, outcome, None).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
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

fn cacheable(operation: &CompiledOperation, source: &SourceRevision) -> bool {
    matches!(operation.access, CompiledAccess::Public)
        && matches!(source, SourceRevision::Snapshot(_))
}

fn negotiate(headers: &HeaderMap) -> Result<Representation, ProblemCode> {
    let Some(value) = headers.get(ACCEPT) else {
        return Ok(Representation::Json);
    };
    let value = value
        .to_str()
        .map_err(|_| ProblemCode::UnsupportedRepresentation)?;
    let mut json = false;
    let mut json_ld = false;
    for item in value.split(',') {
        let mut parts = item.trim().split(';');
        let media = parts.next().unwrap_or_default().trim();
        let refused = parts.any(|parameter| parameter.trim() == "q=0");
        if refused {
            continue;
        }
        match media {
            "application/json" | "application/*" | "*/*" => json = true,
            "application/ld+json" => json_ld = true,
            _ => {}
        }
    }
    if json_ld {
        Ok(Representation::JsonLd)
    } else if json {
        Ok(Representation::Json)
    } else {
        Err(ProblemCode::UnsupportedRepresentation)
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
    let authorization_material = access
        .principal
        .as_ref()
        .map(|principal| principal.authorization_material(&operation.access, &access.authorization))
        .unwrap_or_else(|| b"anonymous".to_vec());
    Ok(CursorPayload::new(
        u64::MAX,
        service.registry.contract_revision.clone(),
        source_revision.to_owned(),
        operation.identifier.clone(),
        CursorBindings {
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
    visible: &[(&CompiledResource, Vec<&CompiledOperation>)],
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
                    .map(|operation| operation.identifier.as_str())
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
    visible: &[(&CompiledResource, Vec<&CompiledOperation>)],
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
) -> Result<Vec<(&'a CompiledResource, Vec<&'a CompiledOperation>)>, ProblemCode> {
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
) -> Result<Vec<&'a CompiledOperation>, ProblemCode> {
    match service.registry.metadata_visibility.resources {
        Visibility::OperatorOnly => Ok(Vec::new()),
        Visibility::Public => Ok(resource
            .operations
            .iter()
            .filter(|operation| matches!(operation.access, CompiledAccess::Public))
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
                .filter(|operation| {
                    authenticator
                        .authorize(&operation.access, Some(principal))
                        .is_ok()
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

fn resource_document(
    service: &RelayService,
    resource: &CompiledResource,
    operations: &[&CompiledOperation],
) -> Value {
    let enumeration = if operations
        .iter()
        .any(|operation| matches!(operation.kind, OperationKind::List))
    {
        if operations.iter().any(|operation| {
            matches!(operation.kind, OperationKind::List)
                && matches!(operation.access, CompiledAccess::Public)
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
        "capabilities": operations.iter().map(|operation| capability(service, resource, operation)).collect::<Vec<_>>(),
        "links": {
            "self": absolute(&service.registry.base_uri, &format!("/v2/resources/{}", resource.id)),
        }
    })
}

fn capability(
    service: &RelayService,
    resource: &CompiledResource,
    operation: &CompiledOperation,
) -> Value {
    let mut document = json!({
        "family": "consultation",
        "pattern": operation_pattern(&operation.kind),
        "resourceIdentifier": resource.id,
        "operationIdentifier": operation.identifier,
        "schemaReference": operation.schema_reference,
        "semanticModelReference": operation.semantic_model_reference,
        "contextReference": operation.context_reference,
        "href": match &operation.kind {
            OperationKind::List => format!("/v2/resources/{}/records", resource.id),
            OperationKind::Read => format!("/v2/resources/{}/records/{{recordIdentifier}}", resource.id),
            OperationKind::Lookup {name} => format!("/v2/resources/{}/lookups/{name}", resource.id),
        }
    });
    let stem = operation_artifact_stem(&resource.id, &operation.kind);
    let object = document
        .as_object_mut()
        .expect("capability document is an object");
    if service.registry.metadata_visibility.classifications != Visibility::OperatorOnly {
        object.insert(
            "classificationReference".into(),
            Value::String(sibling_artifact_reference(
                &operation.schema_reference,
                &format!("{stem}-classifications"),
            )),
        );
    }
    if service.registry.metadata_visibility.processing != Visibility::OperatorOnly {
        object.insert(
            "processingReference".into(),
            Value::String(sibling_artifact_reference(
                &operation.schema_reference,
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
    headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|item| item.trim() == etag))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

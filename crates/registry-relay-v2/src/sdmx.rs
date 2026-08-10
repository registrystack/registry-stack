// SPDX-License-Identifier: Apache-2.0
//! Governed SDMX 2.1 read binding over pre-aggregated statistical views.
//!
//! The binding deliberately implements a small, closed SDMX REST profile. A
//! compiled statistical dataset generates the DSD and reviewed SQL projection; callers can
//! only select exact dimension values, bound the time dimension, and page a
//! deterministic result. Relay never performs dynamic aggregation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, VARY};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, Uri};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_sqlite::{ResultRow, Value as SqlValue};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::audit::{AuditContext, AuditOutcome, PrincipalKind, RelayAudit, RowBoundaryKind};
use crate::auth::{bearer_token, Authorization, AuthorizationError, Principal};
use crate::contract::{Handling, StatisticalValueType};
use crate::model::{
    CompiledAccess, CompiledRegistry, CompiledStatisticalDataset, RowAuthoritySource,
};
use crate::problem::{ProblemCode, TraceContext};
use crate::server::{uri_within_bound, RelayService};
use crate::sqlite_runtime::{
    SdmxConstraint, SdmxOperationQuery, SourceRevision, SqliteRuntimeError,
    MAXIMUM_SDMX_VALUES_PER_DIMENSION, SDMX_MAX_OBSERVATION_COUNT_COLUMN,
    SDMX_OBSERVATION_COUNT_COLUMN, SDMX_PAGE_ROW_PRESENT_COLUMN,
};

const SDMX_JSON: &str = "application/vnd.sdmx.data+json;version=2.1.0";
const SDMX_CSV: &str = "application/vnd.sdmx.data+csv;version=2.1.0";
const SDMX_STRUCTURE_JSON: &str = "application/vnd.sdmx.structure+json;version=2.0.0";
const SDMX_SENDER_ID: &str = "REGISTRY_RELAY";
const MAXIMUM_SERIALIZED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataRepresentation {
    Json,
    Csv,
}

#[derive(Clone)]
struct Access {
    principal: Option<Principal>,
    authorization: Authorization,
}

#[derive(Debug)]
struct DataRequest {
    constraints: BTreeMap<String, SdmxConstraint>,
    offset: u32,
    limit: u32,
    explicit_limit: bool,
    dimension_at_observation: String,
}

struct DataPath {
    context: String,
    agency: String,
    resource: String,
    version: String,
    key: String,
}

struct StructurePath {
    artefact_type: String,
    agency: String,
    resource: String,
    version: String,
}

pub async fn data(
    State(service): State<Arc<RelayService>>,
    Path((context, agency, resource, version, key)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    data_response(
        service,
        DataPath {
            context,
            agency,
            resource,
            version,
            key,
        },
        headers,
        uri,
    )
    .await
}

/// Canonical SDMX data query with every trailing key dimension omitted.
pub async fn data_without_key(
    State(service): State<Arc<RelayService>>,
    Path((context, agency, resource, version)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    data_response(
        service,
        DataPath {
            context,
            agency,
            resource,
            version,
            key: String::new(),
        },
        headers,
        uri,
    )
    .await
}

async fn data_response(
    service: Arc<RelayService>,
    path: DataPath,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let DataPath {
        context,
        agency,
        resource,
        version,
        key,
    } = path;
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return unknown_refusal(
            &service,
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    let principal = match optional_principal(&service, &headers).await {
        Ok(value) => value,
        Err(code) => {
            return unknown_refusal(&service, AuditOutcome::InvalidCredential, code, &trace).await
        }
    };
    let Some(dataflow) = find_dataflow(&service, &context, &agency, &resource, &version) else {
        return unknown_dataflow(&service, principal.as_ref(), &trace).await;
    };
    let access = match authorize(&service, dataflow, principal, false, &trace).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(quota) = service.quota.as_ref() {
        if !quota.admit(&dataflow.operation_identifier()) {
            return refuse_known(
                &service,
                dataflow,
                &access,
                AuditOutcome::RateLimited,
                ProblemCode::RateLimited,
                &trace,
            )
            .await;
        }
    }
    let representation = match negotiate_data(&headers) {
        Ok(value) => value,
        Err(code) => {
            return refuse_known(
                &service,
                dataflow,
                &access,
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await
        }
    };
    let request = match parse_data_request(&service.registry, dataflow, &key, uri.query()) {
        Ok(value) => value,
        Err(code) => {
            return refuse_known(
                &service,
                dataflow,
                &access,
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await
        }
    };
    let audit = audit_context(&service, dataflow, &access, &trace);
    if service.audit.attempt(&audit).await.is_err() {
        return ProblemCode::AuditUnavailable.response(&trace);
    }
    let result = service
        .sqlite
        .execute_sdmx(
            &dataflow.operation_identifier(),
            SdmxOperationQuery {
                constraints: request.constraints,
                row_authority: access.authorization.row_authority.clone(),
                offset: request.offset,
                fetch_limit: request.limit.saturating_add(1),
            },
        )
        .await;
    let mut result = match result {
        Ok(value) => value,
        Err(error) => return source_failure(&service, &audit, error, &trace).await,
    };
    if !normalize_statistical_page(&mut result.rows) {
        return terminal_problem(
            &service,
            &audit,
            AuditOutcome::InternalFailed,
            ProblemCode::Internal,
            &trace,
        )
        .await;
    }
    if result.rows.len() > usize::try_from(request.limit).unwrap_or(usize::MAX) {
        if request.explicit_limit {
            result.rows.pop();
        } else {
            return terminal_problem(
                &service,
                &audit,
                AuditOutcome::InvalidRequest,
                ProblemCode::StatisticalQueryTooLarge,
                &trace,
            )
            .await;
        }
    }
    if result.rows.is_empty() {
        return release_empty(
            &service,
            &audit,
            cacheable(dataflow, &result.source_revision),
            &headers,
            &trace,
        )
        .await;
    }
    if !valid_statistical_rows(&service.registry, dataflow, &result.rows) {
        return terminal_problem(
            &service,
            &audit,
            AuditOutcome::InternalFailed,
            ProblemCode::Internal,
            &trace,
        )
        .await;
    }
    let serialized = match representation {
        DataRepresentation::Json => {
            serialize_data_json(dataflow, &result.rows, &request.dimension_at_observation)
                .map(|bytes| (bytes, SDMX_JSON))
        }
        DataRepresentation::Csv => {
            serialize_data_csv(dataflow, &result.rows).map(|bytes| (bytes, SDMX_CSV))
        }
    };
    let (bytes, content_type) = match serialized {
        Ok(value) => value,
        Err(()) => {
            return terminal_problem(
                &service,
                &audit,
                AuditOutcome::InternalFailed,
                ProblemCode::Internal,
                &trace,
            )
            .await
        }
    };
    release_bytes(
        &service,
        &audit,
        bytes,
        content_type,
        cacheable(dataflow, &result.source_revision),
        &headers,
        &trace,
    )
    .await
}

pub async fn structure(
    State(service): State<Arc<RelayService>>,
    Path((artefact_type, agency, resource, version)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return unknown_refusal(
            &service,
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    let principal = match optional_principal(&service, &headers).await {
        Ok(value) => value,
        Err(code) => {
            return unknown_refusal(&service, AuditOutcome::InvalidCredential, code, &trace).await
        }
    };
    if !matches!(artefact_type.as_str(), "dataflow" | "datastructure") {
        return unknown_refusal(
            &service,
            AuditOutcome::InvalidRequest,
            ProblemCode::StatisticalFeatureUnsupported,
            &trace,
        )
        .await;
    }
    if let Err(code) = validate_structure_query(uri.query()) {
        return unknown_refusal(&service, AuditOutcome::InvalidRequest, code, &trace).await;
    }
    structure_response(
        &service,
        StructurePath {
            artefact_type,
            agency,
            resource,
            version,
        },
        &headers,
        principal,
        &trace,
    )
    .await
}

pub async fn schema(
    State(service): State<Arc<RelayService>>,
    Path((_context, _agency, _resource, _version)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return unknown_refusal(
            &service,
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    if let Err(code) = optional_principal(&service, &headers).await {
        return unknown_refusal(&service, AuditOutcome::InvalidCredential, code, &trace).await;
    }
    unknown_refusal(
        &service,
        AuditOutcome::InvalidRequest,
        ProblemCode::StatisticalFeatureUnsupported,
        &trace,
    )
    .await
}

pub async fn unsupported(
    State(service): State<Arc<RelayService>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    if !uri_within_bound(&uri) {
        return unknown_refusal(
            &service,
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    if let Err(code) = optional_principal(&service, &headers).await {
        return unknown_refusal(&service, AuditOutcome::InvalidCredential, code, &trace).await;
    }
    unknown_refusal(
        &service,
        AuditOutcome::InvalidRequest,
        ProblemCode::StatisticalFeatureUnsupported,
        &trace,
    )
    .await
}

async fn structure_response(
    service: &RelayService,
    path: StructurePath,
    headers: &HeaderMap,
    principal: Option<Principal>,
    trace: &TraceContext,
) -> Response<Body> {
    let StructurePath {
        artefact_type,
        agency,
        resource,
        version,
    } = path;
    let Some(dataflow) = service.registry.statistical_datasets.iter().find(|item| {
        item.sdmx.agency_id == agency
            && match artefact_type.as_str() {
                "dataflow" => item.sdmx.dataflow_id == resource && item.sdmx.version == version,
                "datastructure" => {
                    item.sdmx.data_structure_id == resource && item.sdmx.version == version
                }
                _ => false,
            }
    }) else {
        return unknown_dataflow(service, principal.as_ref(), trace).await;
    };
    let access = match authorize(service, dataflow, principal, true, trace).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(quota) = service.quota.as_ref() {
        if !quota.admit(&dataflow.operation_identifier()) {
            return refuse_known(
                service,
                dataflow,
                &access,
                AuditOutcome::RateLimited,
                ProblemCode::RateLimited,
                trace,
            )
            .await;
        }
    }
    if let Err(code) = negotiate_structure(headers) {
        return refuse_known(
            service,
            dataflow,
            &access,
            AuditOutcome::InvalidRequest,
            code,
            trace,
        )
        .await;
    }
    let audit = audit_context(service, dataflow, &access, trace);
    if service.audit.attempt(&audit).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    let bytes = match bounded_json(&structure_document(
        &service.registry,
        dataflow,
        &artefact_type,
    )) {
        Ok(value) => value,
        Err(()) => {
            return terminal_problem(
                service,
                &audit,
                AuditOutcome::InternalFailed,
                ProblemCode::Internal,
                trace,
            )
            .await
        }
    };
    release_bytes(
        service,
        &audit,
        bytes,
        SDMX_STRUCTURE_JSON,
        service
            .sqlite
            .source_revision(&dataflow.operation_identifier())
            .is_some_and(|source| cacheable(dataflow, source)),
        headers,
        trace,
    )
    .await
}

fn find_dataflow<'a>(
    service: &'a RelayService,
    context: &str,
    agency: &str,
    resource: &str,
    version: &str,
) -> Option<&'a CompiledStatisticalDataset> {
    (context == "dataflow").then_some(())?;
    service.registry.statistical_datasets.iter().find(|item| {
        item.sdmx.agency_id == agency
            && item.sdmx.dataflow_id == resource
            && item.sdmx.version == version
    })
}

fn validate_structure_query(query: Option<&str>) -> Result<(), ProblemCode> {
    let Some(query) = query else {
        return Ok(());
    };
    let mut seen = BTreeSet::new();
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !seen.insert(name.clone()) {
            return Err(ProblemCode::StatisticalQueryInvalid);
        }
        match name.as_ref() {
            "references" if value == "none" => {}
            "references" | "asOf" | "detail" => {
                return Err(ProblemCode::StatisticalFeatureUnsupported)
            }
            _ => return Err(ProblemCode::StatisticalQueryInvalid),
        }
    }
    Ok(())
}

async fn optional_principal(
    service: &RelayService,
    headers: &HeaderMap,
) -> Result<Option<Principal>, ProblemCode> {
    let token = bearer_token(headers).map_err(|_| ProblemCode::InvalidCredential)?;
    let Some(token) = token else {
        return Ok(None);
    };
    service
        .authenticator
        .as_ref()
        .ok_or(ProblemCode::InvalidCredential)?
        .authenticate(token)
        .await
        .map(Some)
        .map_err(|_| ProblemCode::InvalidCredential)
}

async fn authorize(
    service: &RelayService,
    dataflow: &CompiledStatisticalDataset,
    principal: Option<Principal>,
    conceal_denial: bool,
    trace: &TraceContext,
) -> Result<Access, Response<Body>> {
    let result = match &service.authenticator {
        Some(authenticator) => authenticator.authorize(&dataflow.access, principal.as_ref()),
        None => match dataflow.access {
            CompiledAccess::Public => Ok(Authorization {
                row_authority: None,
                purpose: None,
            }),
            CompiledAccess::Protected { .. } => Err(AuthorizationError::AuthenticationRequired),
        },
    };
    match result {
        Ok(authorization) => Ok(Access {
            principal,
            authorization,
        }),
        Err(error) => {
            let (outcome, code) = match error {
                AuthorizationError::AuthenticationRequired => (
                    AuditOutcome::MissingCredential,
                    ProblemCode::MissingCredential,
                ),
                AuthorizationError::ScopeDenied
                | AuthorizationError::PurposeDenied
                | AuthorizationError::BindingDenied => {
                    let code = if conceal_denial {
                        ProblemCode::ResourceNotFound
                    } else {
                        ProblemCode::ConsultationDenied
                    };
                    (AuditOutcome::Denied, code)
                }
            };
            let access = Access {
                principal,
                authorization: Authorization {
                    row_authority: None,
                    purpose: None,
                },
            };
            Err(refuse_known(service, dataflow, &access, outcome, code, trace).await)
        }
    }
}

fn parse_data_request(
    registry: &CompiledRegistry,
    dataflow: &CompiledStatisticalDataset,
    key: &str,
    query: Option<&str>,
) -> Result<DataRequest, ProblemCode> {
    let mut constraints = BTreeMap::new();
    parse_key(dataflow, key, &mut constraints)?;
    let mut offset = 0_u32;
    let mut limit = dataflow.maximum_observations;
    let mut explicit_limit = false;
    let mut dimension_at_observation = dataflow.time.id.clone();
    let mut seen = BTreeSet::new();
    let query = query.unwrap_or_default().replace('+', "%2B");
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let name = name.into_owned();
        let value = value.into_owned();
        if !seen.insert(name.clone()) {
            return Err(ProblemCode::StatisticalQueryInvalid);
        }
        match name.as_str() {
            "offset" => {
                offset = value
                    .parse()
                    .ok()
                    .filter(|value| *value <= dataflow.maximum_offset)
                    .ok_or(ProblemCode::StatisticalQueryInvalid)?;
            }
            "limit" => {
                limit = value
                    .parse()
                    .ok()
                    .filter(|value| *value > 0 && *value <= dataflow.maximum_observations)
                    .ok_or(ProblemCode::StatisticalQueryInvalid)?;
                explicit_limit = true;
            }
            "dimensionAtObservation" => {
                if value != dataflow.time.id && value != "AllDimensions" {
                    return Err(ProblemCode::StatisticalFeatureUnsupported);
                }
                dimension_at_observation = value;
            }
            _ if name.starts_with("c[") && name.ends_with(']') => {
                let id = &name[2..name.len() - 1];
                if constraints.contains_key(id) {
                    return Err(ProblemCode::StatisticalQueryInvalid);
                }
                if let Some(dimension) = dataflow.dimensions.iter().find(|item| item.id == id) {
                    merge_component_constraint(
                        constraints.entry(id.to_owned()).or_default(),
                        dimension.data_type,
                        false,
                        &value,
                    )?;
                } else if id == dataflow.time.id {
                    merge_component_constraint(
                        constraints.entry(id.to_owned()).or_default(),
                        StatisticalValueType::TimePeriod,
                        true,
                        &value,
                    )?;
                } else {
                    return Err(ProblemCode::StatisticalQueryInvalid);
                }
            }
            _ => return Err(ProblemCode::StatisticalFeatureUnsupported),
        }
    }
    if constraints.is_empty() && !dataflow.allow_unfiltered {
        return Err(ProblemCode::StatisticalQueryInvalid);
    }
    if dataflow.dimensions.iter().any(|dimension| {
        dimension.data_type == StatisticalValueType::Code
            && constraints.get(&dimension.id).is_some_and(|constraint| {
                constraint.values.iter().any(|value| {
                    dimension
                        .codelist
                        .as_deref()
                        .is_some_and(|path| !codelist_accepts(registry, Some(path), value))
                })
            })
    }) {
        return Err(ProblemCode::StatisticalQueryInvalid);
    }
    if constraints.values().any(|constraint| {
        constraint
            .lower
            .as_ref()
            .zip(constraint.upper.as_ref())
            .is_some_and(|(lower, upper)| lower > upper)
    }) {
        return Err(ProblemCode::StatisticalQueryInvalid);
    }
    Ok(DataRequest {
        constraints,
        offset,
        limit,
        explicit_limit,
        dimension_at_observation,
    })
}

fn parse_key(
    dataflow: &CompiledStatisticalDataset,
    key: &str,
    constraints: &mut BTreeMap<String, SdmxConstraint>,
) -> Result<(), ProblemCode> {
    if key.is_empty() {
        return Ok(());
    }
    let parts = key.split('.').collect::<Vec<_>>();
    let key_dimensions = &dataflow.dimensions;
    if parts.len() > key_dimensions.len() {
        return Err(ProblemCode::StatisticalQueryInvalid);
    }
    for (index, value) in parts.into_iter().enumerate() {
        if value == "*" {
            continue;
        }
        if value.is_empty() {
            return Err(ProblemCode::StatisticalQueryInvalid);
        }
        let dimension = &key_dimensions[index];
        merge_component_constraint(
            constraints.entry(dimension.id.clone()).or_default(),
            dimension.data_type,
            false,
            value,
        )?;
    }
    Ok(())
}

fn merge_component_constraint(
    constraint: &mut SdmxConstraint,
    data_type: StatisticalValueType,
    time_period: bool,
    text: &str,
) -> Result<(), ProblemCode> {
    let is_range = text
        .split(['+', ','])
        .any(|term| term.starts_with("ge:") || term.starts_with("le:"));
    if (is_range && text.contains(',')) || (!is_range && text.contains('+')) {
        return Err(ProblemCode::StatisticalFeatureUnsupported);
    }
    let separator = if is_range { '+' } else { ',' };
    for term in text.split(separator) {
        if term.is_empty() {
            return Err(ProblemCode::StatisticalQueryInvalid);
        }
        if let Some(value) = term.strip_prefix("ge:") {
            if !time_period || !valid_time_period(value) || constraint.lower.is_some() {
                return Err(ProblemCode::StatisticalQueryInvalid);
            }
            constraint.lower = Some(value.to_owned());
        } else if let Some(value) = term.strip_prefix("le:") {
            if !time_period || !valid_time_period(value) || constraint.upper.is_some() {
                return Err(ProblemCode::StatisticalQueryInvalid);
            }
            constraint.upper = Some(value.to_owned());
        } else {
            let value = term.strip_prefix("eq:").unwrap_or(term);
            constraint
                .values
                .push(parse_component_value(data_type, value)?);
        }
    }
    if constraint.values.len() > MAXIMUM_SDMX_VALUES_PER_DIMENSION {
        return Err(ProblemCode::StatisticalQueryTooLarge);
    }
    Ok(())
}

fn parse_component_value(
    data_type: StatisticalValueType,
    value: &str,
) -> Result<SqlValue, ProblemCode> {
    if value.is_empty() || value.len() > 1024 {
        return Err(ProblemCode::StatisticalQueryInvalid);
    }
    match data_type {
        StatisticalValueType::Code | StatisticalValueType::String => {
            Ok(SqlValue::String(value.to_owned()))
        }
        StatisticalValueType::TimePeriod if valid_time_period(value) => {
            Ok(SqlValue::String(value.to_owned()))
        }
        StatisticalValueType::TimePeriod => Err(ProblemCode::StatisticalQueryInvalid),
        StatisticalValueType::Integer => value
            .parse::<i64>()
            .map(SqlValue::Integer)
            .map_err(|_| ProblemCode::StatisticalQueryInvalid),
        StatisticalValueType::Decimal => value
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
            .map(SqlValue::Number)
            .ok_or(ProblemCode::StatisticalQueryInvalid),
        StatisticalValueType::Boolean => match value {
            "true" => Ok(SqlValue::Boolean(true)),
            "false" => Ok(SqlValue::Boolean(false)),
            _ => Err(ProblemCode::StatisticalQueryInvalid),
        },
    }
}

fn valid_statistical_rows(
    registry: &CompiledRegistry,
    dataflow: &CompiledStatisticalDataset,
    rows: &[ResultRow],
) -> bool {
    let mut observation_keys = BTreeSet::new();
    for row in rows {
        if row.get(SDMX_OBSERVATION_COUNT_COLUMN) != Some(&SqlValue::Integer(1)) {
            return false;
        }
        let mut key = Vec::with_capacity(dataflow.dimensions.len().saturating_add(1));
        for dimension in &dataflow.dimensions {
            let Some(value) = row.get(&dimension.source_column) else {
                return false;
            };
            if matches!(value, SqlValue::Null)
                || !codelist_accepts(registry, dimension.codelist.as_deref(), value)
            {
                return false;
            }
            key.push(stable_value(value));
        }
        let Some(time) = row.get(&dataflow.time.source_column) else {
            return false;
        };
        if !matches!(time, SqlValue::String(value) if valid_time_period(value)) {
            return false;
        }
        key.push(stable_value(time));
        if !observation_keys.insert(key) {
            return false;
        }
        if row
            .get(&dataflow.measure.source_column)
            .is_none_or(|value| matches!(value, SqlValue::Null))
        {
            return false;
        }
        for attribute in &dataflow.attributes {
            let Some(value) = row.get(&attribute.source_column) else {
                return false;
            };
            if matches!(value, SqlValue::Null) {
                if attribute.source_required {
                    return false;
                }
            } else if !codelist_accepts(registry, attribute.codelist.as_deref(), value) {
                return false;
            }
        }
    }
    true
}

fn normalize_statistical_page(rows: &mut Vec<ResultRow>) -> bool {
    let Some(maximum_observation_count) = rows
        .first()
        .and_then(|row| row.get(SDMX_MAX_OBSERVATION_COUNT_COLUMN))
    else {
        return false;
    };
    if !matches!(maximum_observation_count, SqlValue::Integer(0 | 1))
        || rows.iter().any(|row| {
            row.get(SDMX_MAX_OBSERVATION_COUNT_COLUMN) != Some(maximum_observation_count)
        })
    {
        return false;
    }
    let page_is_empty = rows
        .first()
        .and_then(|row| row.get(SDMX_PAGE_ROW_PRESENT_COLUMN))
        == Some(&SqlValue::Integer(0));
    if page_is_empty {
        if rows.len() != 1 {
            return false;
        }
        rows.clear();
        return true;
    }
    rows.iter().all(|row| {
        row.get(SDMX_PAGE_ROW_PRESENT_COLUMN) == Some(&SqlValue::Integer(1))
            && maximum_observation_count == &SqlValue::Integer(1)
    })
}

fn codelist_accepts(registry: &CompiledRegistry, path: Option<&str>, value: &SqlValue) -> bool {
    let Some(path) = path else {
        return true;
    };
    let SqlValue::String(value) = value else {
        return false;
    };
    registry
        .codelists
        .iter()
        .find(|codelist| codelist.path == path)
        .is_some_and(|codelist| codelist.values.iter().any(|candidate| candidate == value))
}

fn negotiate_data(headers: &HeaderMap) -> Result<DataRepresentation, ProblemCode> {
    let Some(value) = headers.get(ACCEPT) else {
        return Ok(DataRepresentation::Json);
    };
    let value = value
        .to_str()
        .map_err(|_| ProblemCode::UnsupportedRepresentation)?;
    let mut selected = None::<(u16, usize, DataRepresentation)>;
    for (index, item) in value.split(',').enumerate() {
        let mut parts = item.trim().split(';').map(str::trim);
        let media = parts.next().unwrap_or_default();
        let mut quality = 1000;
        let mut version = None;
        let mut seen_quality = false;
        let mut supported_parameters = true;
        for parameter in parts {
            if let Some(value) = parameter.strip_prefix("q=") {
                if seen_quality {
                    supported_parameters = false;
                    break;
                }
                let Some(value) = parse_quality(value) else {
                    supported_parameters = false;
                    break;
                };
                seen_quality = true;
                quality = value;
            } else if let Some(value) = parameter.strip_prefix("version=") {
                if version.is_some() {
                    supported_parameters = false;
                    break;
                }
                version = Some(value);
            } else {
                supported_parameters = false;
                break;
            }
        }
        if !supported_parameters || quality == 0 {
            continue;
        }
        let representation = match media {
            "application/vnd.sdmx.data+json" if version.is_none_or(|value| value == "2.1.0") => {
                Some(DataRepresentation::Json)
            }
            "application/vnd.sdmx.data+csv" if version.is_none_or(|value| value == "2.1.0") => {
                Some(DataRepresentation::Csv)
            }
            "application/json" | "*/*" if version.is_none() => Some(DataRepresentation::Json),
            "text/csv" if version.is_none() => Some(DataRepresentation::Csv),
            _ => None,
        };
        if let Some(representation) = representation {
            let candidate = (quality, usize::MAX - index, representation);
            if selected.as_ref().is_none_or(|current| {
                candidate.0 > current.0 || candidate.0 == current.0 && candidate.1 > current.1
            }) {
                selected = Some(candidate);
            }
        }
    }
    selected
        .map(|(_, _, representation)| representation)
        .ok_or(ProblemCode::UnsupportedRepresentation)
}

fn negotiate_structure(headers: &HeaderMap) -> Result<(), ProblemCode> {
    let Some(value) = headers.get(ACCEPT) else {
        return Ok(());
    };
    let value = value
        .to_str()
        .map_err(|_| ProblemCode::UnsupportedRepresentation)?;
    let mut selected = None::<(u16, usize)>;
    for (index, item) in value.split(',').enumerate() {
        let mut parts = item.trim().split(';').map(str::trim);
        let media = parts.next().unwrap_or_default();
        let mut quality = 1000;
        let mut version = None;
        let mut seen_quality = false;
        let mut supported_parameters = true;
        for parameter in parts {
            if let Some(value) = parameter.strip_prefix("q=") {
                if seen_quality {
                    supported_parameters = false;
                    break;
                }
                let Some(value) = parse_quality(value) else {
                    supported_parameters = false;
                    break;
                };
                seen_quality = true;
                quality = value;
            } else if let Some(value) = parameter.strip_prefix("version=") {
                if version.is_some() {
                    supported_parameters = false;
                    break;
                }
                version = Some(value);
            } else {
                supported_parameters = false;
                break;
            }
        }
        if !supported_parameters || quality == 0 {
            continue;
        }
        let supported = (media == "application/vnd.sdmx.structure+json"
            && version.is_none_or(|value| value == "2.0.0"))
            || ((media == "application/json" || media == "*/*") && version.is_none());
        if supported {
            let candidate = (quality, usize::MAX - index);
            if selected.as_ref().is_none_or(|current| {
                candidate.0 > current.0 || candidate.0 == current.0 && candidate.1 > current.1
            }) {
                selected = Some(candidate);
            }
        }
    }
    selected
        .map(|_| ())
        .ok_or(ProblemCode::UnsupportedRepresentation)
}

fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let padded = format!("{fraction:0<3}");
    match whole {
        "0" => padded.parse().ok(),
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

fn valid_time_period(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() == 4 {
        return bytes.iter().all(u8::is_ascii_digit);
    }
    if bytes.len() == 7
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5] == b'Q'
        && matches!(bytes[6], b'1'..=b'4')
    {
        return true;
    }
    if bytes.len() == 7
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..].iter().all(u8::is_ascii_digit)
    {
        return value[5..]
            .parse::<u8>()
            .is_ok_and(|month| (1..=12).contains(&month));
    }
    if bytes.len() == 10
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..].iter().all(u8::is_ascii_digit)
    {
        return chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok();
    }
    false
}

fn serialize_data_json(
    dataflow: &CompiledStatisticalDataset,
    rows: &[ResultRow],
    dimension_at_observation: &str,
) -> Result<Vec<u8>, ()> {
    if dimension_at_observation == "AllDimensions" {
        return serialize_flat_json(dataflow, rows);
    }
    serialize_series_json(dataflow, rows)
}

fn serialize_flat_json(
    dataflow: &CompiledStatisticalDataset,
    rows: &[ResultRow],
) -> Result<Vec<u8>, ()> {
    let (dimensions, indexes) = dimension_metadata(dataflow, rows)?;
    let attributes = attribute_metadata(dataflow, rows)?;
    let mut observations = Map::new();
    for row in rows {
        let key = dataflow
            .dimensions
            .iter()
            .map(|dimension| {
                let value = row.get(&dimension.source_column).ok_or(())?;
                indexes
                    .get(&dimension.id)
                    .and_then(|items| items.get(&stable_value(value)))
                    .copied()
                    .ok_or(())
                    .map(|value| value.to_string())
            })
            .chain(std::iter::once(&dataflow.time).map(|time| {
                let value = row.get(&time.source_column).ok_or(())?;
                indexes
                    .get(&time.id)
                    .and_then(|items| items.get(&stable_value(value)))
                    .copied()
                    .ok_or(())
                    .map(|value| value.to_string())
            }))
            .collect::<Result<Vec<_>, _>>()?
            .join(":");
        observations.insert(key, observation_values(dataflow, row, &attributes)?);
    }
    bounded_json(&json!({
        "$schema": "https://json.sdmx.org/2.1/sdmx-json-data-schema.json",
        "meta": message_meta(dataflow),
        "data": {
            "dataSets": [{"structure": 0, "action": "Replace", "observations": observations}],
            "structures": [{
                "links": [dataflow_link(dataflow, "dataflow")],
                "name": dataflow.title,
                "description": dataflow.description,
                "dataSets": [0],
                "dimensions": {"observation": dimensions},
                "measures": {"observation": [measure_document(dataflow)]},
                "attributes": {"observation": attributes.iter().map(|item| item.document.clone()).collect::<Vec<_>>()}
            }]
        }
    }))
}

fn serialize_series_json(
    dataflow: &CompiledStatisticalDataset,
    rows: &[ResultRow],
) -> Result<Vec<u8>, ()> {
    let time = &dataflow.time;
    let series_dimensions = &dataflow.dimensions;
    let (all_dimensions, indexes) = dimension_metadata(dataflow, rows)?;
    let dimensions_by_id = all_dimensions
        .into_iter()
        .map(|value| {
            let id = value
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            (id, value)
        })
        .collect::<BTreeMap<_, _>>();
    let attributes = attribute_metadata(dataflow, rows)?;
    let mut series = Map::new();
    let mut observations = Map::new();
    for row in rows {
        let series_key = series_dimensions
            .iter()
            .map(|dimension| {
                indexes
                    .get(&dimension.id)
                    .and_then(|items| items.get(&stable_value(row.get(&dimension.source_column)?)))
                    .copied()
                    .map(|value| value.to_string())
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(())?
            .join(":");
        let time_key = indexes
            .get(&time.id)
            .and_then(|items| items.get(&stable_value(row.get(&time.source_column)?)))
            .copied()
            .ok_or(())?
            .to_string();
        if series_dimensions.is_empty() {
            observations.insert(time_key, observation_values(dataflow, row, &attributes)?);
        } else {
            let entry = series
                .entry(series_key)
                .or_insert_with(|| json!({"observations": {}}));
            entry
                .get_mut("observations")
                .and_then(Value::as_object_mut)
                .ok_or(())?
                .insert(time_key, observation_values(dataflow, row, &attributes)?);
        }
    }
    let data_set = if series_dimensions.is_empty() {
        json!({"structure": 0, "action": "Replace", "observations": observations})
    } else {
        json!({"structure": 0, "action": "Replace", "series": series})
    };
    bounded_json(&json!({
        "$schema": "https://json.sdmx.org/2.1/sdmx-json-data-schema.json",
        "meta": message_meta(dataflow),
        "data": {
            "dataSets": [data_set],
            "structures": [{
                "links": [dataflow_link(dataflow, "dataflow")],
                "name": dataflow.title,
                "description": dataflow.description,
                "dataSets": [0],
                "dimensions": {
                    "series": series_dimensions.iter().filter_map(|item| dimensions_by_id.get(&item.id)).cloned().collect::<Vec<_>>(),
                    "observation": [dimensions_by_id.get(&time.id).cloned().ok_or(())?]
                },
                "measures": {"observation": [measure_document(dataflow)]},
                "attributes": {"observation": attributes.iter().map(|item| item.document.clone()).collect::<Vec<_>>()}
            }]
        }
    }))
}

type ValueIndex = BTreeMap<String, usize>;
type DimensionMetadata = (Vec<Value>, BTreeMap<String, ValueIndex>);

struct AttributeMetadata {
    document: Value,
    indexes: Option<ValueIndex>,
}

type AttributeIndex = Vec<AttributeMetadata>;

fn dimension_metadata(
    dataflow: &CompiledStatisticalDataset,
    rows: &[ResultRow],
) -> Result<DimensionMetadata, ()> {
    let mut documents = Vec::new();
    let mut indexes = BTreeMap::new();
    for dimension in &dataflow.dimensions {
        let values = unique_values(rows, &dimension.source_column)?;
        let index = values
            .iter()
            .enumerate()
            .map(|(index, value)| (stable_value(value), index))
            .collect::<BTreeMap<_, _>>();
        documents.push(json!({
            "id": dimension.id,
            "name": dimension.label,
            "description": dimension.description,
            "keyPosition": documents.len(),
            "roles": [],
            "values": values.iter().map(value_document).collect::<Vec<_>>()
        }));
        indexes.insert(dimension.id.clone(), index);
    }
    let time_values = unique_values(rows, &dataflow.time.source_column)?;
    let time_index = time_values
        .iter()
        .enumerate()
        .map(|(index, value)| (stable_value(value), index))
        .collect::<BTreeMap<_, _>>();
    documents.push(json!({
        "id": dataflow.time.id,
        "name": dataflow.time.label,
        "description": dataflow.time.description,
        "keyPosition": documents.len(),
        "roles": ["TIME_PERIOD"],
        "values": time_values.iter().map(value_document).collect::<Vec<_>>()
    }));
    indexes.insert(dataflow.time.id.clone(), time_index);
    Ok((documents, indexes))
}

fn attribute_metadata(
    dataflow: &CompiledStatisticalDataset,
    rows: &[ResultRow],
) -> Result<AttributeIndex, ()> {
    dataflow
        .attributes
        .iter()
        .map(|attribute| {
            let values = unique_values(rows, &attribute.source_column)?;
            let mut document = json!({
                "id": attribute.id,
                "name": attribute.label,
                "description": attribute.description,
                "isMandatory": attribute.source_required,
                "relationship": {"observation": {}},
            });
            let indexes = if attribute.data_type == StatisticalValueType::Code {
                document.as_object_mut().ok_or(())?.insert(
                    "values".into(),
                    json!(values.iter().map(value_document).collect::<Vec<_>>()),
                );
                Some(
                    values
                        .iter()
                        .enumerate()
                        .map(|(index, value)| (stable_value(value), index))
                        .collect::<BTreeMap<_, _>>(),
                )
            } else {
                document.as_object_mut().ok_or(())?.insert(
                    "format".into(),
                    json!({"dataType": statistical_data_type(attribute.data_type)}),
                );
                None
            };
            Ok(AttributeMetadata { document, indexes })
        })
        .collect()
}

fn observation_values(
    dataflow: &CompiledStatisticalDataset,
    row: &ResultRow,
    attributes: &AttributeIndex,
) -> Result<Value, ()> {
    let mut values = vec![sql_json(
        row.get(&dataflow.measure.source_column).ok_or(())?,
    )];
    for (index, attribute) in dataflow.attributes.iter().enumerate() {
        let value = row.get(&attribute.source_column).ok_or(())?;
        values.push(match value {
            SqlValue::Null => Value::Null,
            _ => match &attributes[index].indexes {
                Some(indexes) => Value::from(indexes.get(&stable_value(value)).copied().ok_or(())?),
                None => sql_json(value),
            },
        });
    }
    Ok(Value::Array(values))
}

fn serialize_data_csv(
    dataflow: &CompiledStatisticalDataset,
    rows: &[ResultRow],
) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    let mut header = vec!["STRUCTURE", "STRUCTURE_ID", "ACTION"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    header.extend(dataflow.dimensions.iter().map(|item| item.id.clone()));
    header.push(dataflow.time.id.clone());
    header.push(dataflow.measure.id.clone());
    header.extend(dataflow.attributes.iter().map(|item| item.id.clone()));
    write_csv_row(&mut bytes, &header)?;
    for row in rows {
        let mut values = vec![
            "dataflow".to_owned(),
            format!(
                "{}:{}({})",
                dataflow.sdmx.agency_id, dataflow.sdmx.dataflow_id, dataflow.sdmx.version
            ),
            "R".to_owned(),
        ];
        values.extend(
            dataflow
                .dimensions
                .iter()
                .map(|item| csv_value(row.get(&item.source_column)))
                .collect::<Result<Vec<_>, _>>()?,
        );
        values.push(csv_value(row.get(&dataflow.time.source_column))?);
        values.push(csv_value(row.get(&dataflow.measure.source_column))?);
        values.extend(
            dataflow
                .attributes
                .iter()
                .map(|item| csv_value(row.get(&item.source_column)))
                .collect::<Result<Vec<_>, _>>()?,
        );
        write_csv_row(&mut bytes, &values)?;
        if bytes.len() > MAXIMUM_SERIALIZED_BYTES {
            return Err(());
        }
    }
    Ok(bytes)
}

fn write_csv_row(bytes: &mut Vec<u8>, values: &[String]) -> Result<(), ()> {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        let escaped = value.replace('"', "\"\"");
        if value.contains([',', '"', '\n', '\r']) {
            write!(bytes, "\"{escaped}\"").map_err(|_| ())?;
        } else {
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    bytes.push(b'\n');
    Ok(())
}

fn unique_values(rows: &[ResultRow], column: &str) -> Result<Vec<SqlValue>, ()> {
    let mut values = BTreeMap::new();
    for row in rows {
        let value = row.get(column).ok_or(())?;
        if !matches!(value, SqlValue::Null) {
            values
                .entry(stable_value(value))
                .or_insert_with(|| value.clone());
        }
    }
    Ok(values.into_values().collect())
}

fn stable_value(value: &SqlValue) -> String {
    match value {
        SqlValue::Null => "null:".to_owned(),
        SqlValue::String(value) => format!("s:{value}"),
        SqlValue::Integer(value) => format!("i:{value}"),
        SqlValue::Number(value) => format!("n:{value}"),
        SqlValue::Boolean(value) => format!("b:{value}"),
    }
}

fn sql_json(value: &SqlValue) -> Value {
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::String(value) => Value::String(value.clone()),
        SqlValue::Integer(value) => Value::from(*value),
        SqlValue::Number(value) => json!(value),
        SqlValue::Boolean(value) => Value::Bool(*value),
    }
}

fn value_document(value: &SqlValue) -> Value {
    let value = csv_value(Some(value)).unwrap_or_default();
    json!({"id": value, "name": value})
}

fn csv_value(value: Option<&SqlValue>) -> Result<String, ()> {
    Ok(match value.ok_or(())? {
        SqlValue::Null => String::new(),
        SqlValue::String(value) => value.clone(),
        SqlValue::Integer(value) => value.to_string(),
        SqlValue::Number(value) => value.to_string(),
        SqlValue::Boolean(value) => value.to_string(),
    })
}

fn measure_document(dataflow: &CompiledStatisticalDataset) -> Value {
    json!({
        "id": dataflow.measure.id,
        "name": dataflow.measure.label,
        "description": dataflow.measure.description,
        "isMandatory": true,
        "format": {"dataType": statistical_data_type(dataflow.measure.data_type)},
    })
}

fn message_meta(dataflow: &CompiledStatisticalDataset) -> Value {
    json!({
        "id": message_identifier(dataflow, "data"),
        "test": false,
        "prepared": dataflow.release_at,
        "sender": {"id": SDMX_SENDER_ID},
    })
}

fn message_identifier(dataflow: &CompiledStatisticalDataset, suffix: &str) -> String {
    schema_safe_message_identifier(
        &dataflow.sdmx.agency_id,
        &dataflow.sdmx.dataflow_id,
        &dataflow.sdmx.version,
        suffix,
    )
}

fn schema_safe_message_identifier(
    agency_id: &str,
    dataflow_id: &str,
    version: &str,
    suffix: &str,
) -> String {
    format!(
        "{}_{}_{}_{}",
        agency_id.replace('.', "_"),
        dataflow_id.replace('.', "_"),
        version.replace('.', "_"),
        suffix
    )
}

fn dataflow_urn(dataflow: &CompiledStatisticalDataset) -> String {
    format!(
        "urn:sdmx:org.sdmx.infomodel.datastructure.Dataflow={}:{}({})",
        dataflow.sdmx.agency_id, dataflow.sdmx.dataflow_id, dataflow.sdmx.version
    )
}

fn data_structure_urn(dataflow: &CompiledStatisticalDataset) -> String {
    format!(
        "urn:sdmx:org.sdmx.infomodel.datastructure.DataStructure={}:{}({})",
        dataflow.sdmx.agency_id, dataflow.sdmx.data_structure_id, dataflow.sdmx.version
    )
}

fn dataflow_link(dataflow: &CompiledStatisticalDataset, relationship: &str) -> Value {
    json!({"urn": dataflow_urn(dataflow), "rel": relationship})
}

fn statistical_data_type(value: StatisticalValueType) -> &'static str {
    match value {
        StatisticalValueType::Code | StatisticalValueType::String => "String",
        StatisticalValueType::TimePeriod => "ObservationalTimePeriod",
        StatisticalValueType::Integer => "Integer",
        StatisticalValueType::Decimal => "Decimal",
        StatisticalValueType::Boolean => "Boolean",
    }
}

pub(crate) fn structure_document(
    _registry: &CompiledRegistry,
    dataflow: &CompiledStatisticalDataset,
    artefact_type: &str,
) -> Value {
    let data = match artefact_type {
        "dataflow" => json!({"dataflows": [dataflow_structure(dataflow)]}),
        "datastructure" => json!({"dataStructures": [data_structure(dataflow)]}),
        _ => json!({}),
    };
    structure_message(dataflow, data)
}

fn structure_message(dataflow: &CompiledStatisticalDataset, data: Value) -> Value {
    json!({
        "meta": {
            "schema": "https://json.sdmx.org/2.0.0/sdmx-json-structure-schema.json",
            "id": message_identifier(dataflow, "structure"),
            "test": false,
            "prepared": dataflow.release_at,
            "sender": {"id": SDMX_SENDER_ID},
        },
        "data": data,
    })
}

fn dataflow_structure(dataflow: &CompiledStatisticalDataset) -> Value {
    json!({
        "id": dataflow.sdmx.dataflow_id,
        "agencyID": dataflow.sdmx.agency_id,
        "version": dataflow.sdmx.version,
        "name": dataflow.title,
        "description": dataflow.description,
        "links": [{"urn": dataflow_urn(dataflow), "rel": "self"}],
        "structure": data_structure_urn(dataflow),
    })
}

fn data_structure(dataflow: &CompiledStatisticalDataset) -> Value {
    let non_time_dimensions = dataflow
        .dimensions
        .iter()
        .enumerate()
        .map(|(position, component)| {
            json!({
                "id": component.id,
                "position": position,
                "conceptIdentity": concept_urn(dataflow, &component.id),
                "localRepresentation": component_representation(dataflow, &component.id, component.codelist.as_deref(), component.data_type),
            })
        })
        .collect::<Vec<_>>();
    let time_dimension = json!({
        "id": dataflow.time.id,
        "position": dataflow.dimensions.len(),
        "conceptIdentity": concept_urn(dataflow, &dataflow.time.id),
        "localRepresentation": {"format": {"dataType": "ObservationalTimePeriod"}},
    });
    let mut dimension_list = Map::new();
    dimension_list.insert("id".into(), json!("DimensionDescriptor"));
    if !non_time_dimensions.is_empty() {
        dimension_list.insert("dimensions".into(), json!(non_time_dimensions));
    }
    dimension_list.insert("timeDimension".into(), time_dimension);

    let mut components = Map::new();
    components.insert("dimensionList".into(), Value::Object(dimension_list));
    components.insert(
        "measureList".into(),
        json!({
            "id": "MeasureDescriptor",
            "measures": [{
                "id": dataflow.measure.id,
                "usage": "mandatory",
                "conceptIdentity": concept_urn(dataflow, &dataflow.measure.id),
                "localRepresentation": {"format": {"dataType": statistical_data_type(dataflow.measure.data_type)}},
            }],
        }),
    );
    if !dataflow.attributes.is_empty() {
        components.insert(
            "attributeList".into(),
            json!({
                "id": "AttributeDescriptor",
                "attributes": dataflow.attributes.iter().map(|component| json!({
                    "id": component.id,
                    "usage": if component.source_required {"mandatory"} else {"optional"},
                    "attributeRelationship": {"observation": {}},
                    "conceptIdentity": concept_urn(dataflow, &component.id),
                    "localRepresentation": component_representation(dataflow, &component.id, component.codelist.as_deref(), component.data_type),
                })).collect::<Vec<_>>(),
            }),
        );
    }

    json!({
        "id": dataflow.sdmx.data_structure_id,
        "agencyID": dataflow.sdmx.agency_id,
        "version": dataflow.sdmx.version,
        "name": dataflow.title,
        "description": dataflow.description,
        "links": [{"urn": data_structure_urn(dataflow), "rel": "self"}],
        "dataStructureComponents": Value::Object(components),
    })
}

fn component_representation(
    dataflow: &CompiledStatisticalDataset,
    component_id: &str,
    codelist_path: Option<&str>,
    data_type: StatisticalValueType,
) -> Value {
    if codelist_path.is_some() {
        return json!({"enumeration": codelist_urn(dataflow, component_id)});
    }
    json!({"format": {"dataType": statistical_data_type(data_type)}})
}

fn concept_urn(dataflow: &CompiledStatisticalDataset, component_id: &str) -> String {
    format!(
        "urn:sdmx:org.sdmx.infomodel.conceptscheme.Concept={}:{}({}).{}",
        dataflow.sdmx.agency_id,
        dataflow.sdmx.concept_scheme_id,
        dataflow.sdmx.version,
        component_id
    )
}

fn codelist_urn(dataflow: &CompiledStatisticalDataset, component_id: &str) -> String {
    format!(
        "urn:sdmx:org.sdmx.infomodel.codelist.Codelist={}:CL_{}({})",
        dataflow.sdmx.agency_id, component_id, dataflow.sdmx.version
    )
}

fn bounded_json(value: &Value) -> Result<Vec<u8>, ()> {
    let bytes = canonicalize_json(value).map_err(|_| ())?;
    (bytes.len() <= MAXIMUM_SERIALIZED_BYTES)
        .then_some(bytes)
        .ok_or(())
}

async fn release_bytes(
    service: &RelayService,
    audit: &AuditContext,
    bytes: Vec<u8>,
    content_type: &'static str,
    cacheable: bool,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Response<Body> {
    let etag = cacheable.then(|| exact_etag(&bytes));
    if etag
        .as_deref()
        .is_some_and(|tag| matches_etag(headers, tag))
    {
        if service
            .audit
            .terminal(audit, AuditOutcome::NotModified, None)
            .await
            .is_err()
        {
            return ProblemCode::AuditUnavailable.response(trace);
        }
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        apply_cache_headers(response.headers_mut(), true, etag.as_deref());
        trace.apply(response.headers_mut());
        return response;
    }
    if service
        .audit
        .terminal(audit, AuditOutcome::Released, Some(&bytes))
        .await
        .is_err()
    {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    response_bytes(bytes, content_type, cacheable, etag.as_deref(), trace)
}

async fn release_empty(
    service: &RelayService,
    audit: &AuditContext,
    cacheable: bool,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Response<Body> {
    let etag = cacheable.then(|| exact_etag(&[]));
    let not_modified = etag
        .as_deref()
        .is_some_and(|tag| matches_etag(headers, tag));
    let outcome = if not_modified {
        AuditOutcome::NotModified
    } else {
        AuditOutcome::Released
    };
    if service
        .audit
        .terminal(audit, outcome, (!not_modified).then_some(&[][..]))
        .await
        .is_err()
    {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    let mut response = Response::new(Body::empty());
    *response.status_mut() = if not_modified {
        StatusCode::NOT_MODIFIED
    } else {
        StatusCode::NO_CONTENT
    };
    apply_cache_headers(response.headers_mut(), cacheable, etag.as_deref());
    trace.apply(response.headers_mut());
    response
}

fn response_bytes(
    bytes: Vec<u8>,
    content_type: &'static str,
    cacheable: bool,
    etag: Option<&str>,
    trace: &TraceContext,
) -> Response<Body> {
    let mut response = Response::new(Body::from(bytes));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    apply_cache_headers(response.headers_mut(), cacheable, etag);
    trace.apply(response.headers_mut());
    response
}

fn apply_cache_headers(headers: &mut HeaderMap, cacheable: bool, etag: Option<&str>) {
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static(if cacheable {
            "public, no-cache"
        } else {
            "no-store"
        }),
    );
    headers.insert(VARY, HeaderValue::from_static("Accept, Authorization"));
    if let Some(etag) = etag.and_then(|value| HeaderValue::from_str(value).ok()) {
        headers.insert(ETAG, etag);
    }
}

fn exact_etag(bytes: &[u8]) -> String {
    format!("\"sha256-{}\"", hex::encode(Sha256::digest(bytes)))
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|item| item.trim() == etag))
}

fn cacheable(dataflow: &CompiledStatisticalDataset, source: &SourceRevision) -> bool {
    matches!(dataflow.access, CompiledAccess::Public)
        && matches!(source, SourceRevision::Snapshot(_))
}

fn audit_context(
    service: &RelayService,
    dataflow: &CompiledStatisticalDataset,
    access: &Access,
    trace: &TraceContext,
) -> AuditContext {
    AuditContext {
        operation_id: RelayAudit::operation_id(),
        trace_id: trace.trace_id.clone(),
        registry_identifier: service.registry.registry_identifier.clone(),
        resource_identifier: Some(dataflow.id.clone()),
        operation_identifier: Some(dataflow.operation_identifier()),
        access_rule_revision: access_revision(&dataflow.access),
        purpose: access.authorization.purpose.clone(),
        row_boundary_kind: row_boundary(&dataflow.access),
        representation: Some("sdmx".into()),
        disclosure_profile: Some("sdmx-dsd".into()),
        processing_description_identifiers: dataflow
            .processing_descriptions
            .iter()
            .map(|item| item.id.clone())
            .collect(),
        selected_properties: dataflow
            .dimensions
            .iter()
            .map(|item| item.id.clone())
            .chain(std::iter::once(dataflow.time.id.clone()))
            .chain(std::iter::once(dataflow.measure.id.clone()))
            .chain(dataflow.attributes.iter().map(|item| item.id.clone()))
            .collect(),
        processing_handling: Some(handling_label(dataflow.processing_handling).into()),
        disclosure_handling: Some(handling_label(dataflow.disclosure_handling).into()),
        transform_identifiers: Vec::new(),
        contract_revision: service.registry.contract_revision.clone(),
        source_revision: service
            .sqlite
            .source_revision(&dataflow.operation_identifier())
            .cloned(),
        principal_kind: if access.principal.is_some() {
            PrincipalKind::Authenticated
        } else {
            PrincipalKind::Anonymous
        },
    }
}

fn unknown_audit_context(service: &RelayService, trace: &TraceContext) -> AuditContext {
    AuditContext {
        operation_id: RelayAudit::operation_id(),
        trace_id: trace.trace_id.clone(),
        registry_identifier: service.registry.registry_identifier.clone(),
        resource_identifier: None,
        operation_identifier: None,
        access_rule_revision: None,
        purpose: None,
        row_boundary_kind: RowBoundaryKind::Unknown,
        representation: None,
        disclosure_profile: None,
        processing_description_identifiers: Vec::new(),
        selected_properties: Vec::new(),
        processing_handling: None,
        disclosure_handling: None,
        transform_identifiers: Vec::new(),
        contract_revision: service.registry.contract_revision.clone(),
        source_revision: None,
        principal_kind: PrincipalKind::Unknown,
    }
}

async fn refuse_known(
    service: &RelayService,
    dataflow: &CompiledStatisticalDataset,
    access: &Access,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    let context = audit_context(service, dataflow, access, trace);
    if service.audit.refusal(&context, outcome).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

async fn unknown_refusal(
    service: &RelayService,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    let context = unknown_audit_context(service, trace);
    if service.audit.refusal(&context, outcome).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

async fn unknown_dataflow(
    service: &RelayService,
    principal: Option<&Principal>,
    trace: &TraceContext,
) -> Response<Body> {
    let protected = service
        .registry
        .statistical_datasets
        .iter()
        .any(|item| matches!(item.access, CompiledAccess::Protected { .. }));
    let code = if protected && principal.is_none() {
        ProblemCode::MissingCredential
    } else {
        ProblemCode::ResourceNotFound
    };
    let outcome = if code == ProblemCode::MissingCredential {
        AuditOutcome::MissingCredential
    } else {
        AuditOutcome::NotFound
    };
    unknown_refusal(service, outcome, code, trace).await
}

async fn source_failure(
    service: &RelayService,
    audit: &AuditContext,
    error: SqliteRuntimeError,
    trace: &TraceContext,
) -> Response<Body> {
    let (outcome, code) = match error {
        SqliteRuntimeError::AdmissionTimeout => (AuditOutcome::TimedOut, ProblemCode::Timeout),
        SqliteRuntimeError::Source(_) => {
            (AuditOutcome::SourceFailed, ProblemCode::SourceUnavailable)
        }
        _ => (AuditOutcome::InternalFailed, ProblemCode::Internal),
    };
    terminal_problem(service, audit, outcome, code, trace).await
}

async fn terminal_problem(
    service: &RelayService,
    audit: &AuditContext,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    if service.audit.terminal(audit, outcome, None).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

fn access_revision(access: &CompiledAccess) -> Option<String> {
    let value = serde_json::to_value(access).ok()?;
    let bytes = canonicalize_json(&value).ok()?;
    Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn row_boundary(access: &CompiledAccess) -> RowBoundaryKind {
    match access {
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

const fn handling_label(value: Handling) -> &'static str {
    match value {
        Handling::Public => "public",
        Handling::Internal => "internal",
        Handling::Confidential => "confidential",
        Handling::Restricted => "restricted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statistical_dataflow() -> CompiledStatisticalDataset {
        let classification = crate::model::EffectiveClassification {
            privacy: "non-personal".into(),
            privacy_scheme: "urn:privacy".into(),
            privacy_version: "1".into(),
            institutional: "public".into(),
            institutional_scheme: "urn:institutional".into(),
            institutional_version: "1".into(),
            handling: Handling::Public,
            handling_scheme: "urn:handling".into(),
            handling_version: "1".into(),
            status: crate::contract::ReviewStatus::Reviewed,
            provenance_ref: "governance/review.yaml".into(),
        };
        CompiledStatisticalDataset {
            id: "rates".into(),
            title: "Rates".into(),
            description: "Reviewed rates".into(),
            sdmx: crate::model::CompiledSdmxBinding {
                agency_id: "EXAMPLE.STAT".into(),
                dataflow_id: "RATES".into(),
                version: "2.3.4".into(),
                data_structure_id: "RATES_DSD".into(),
                concept_scheme_id: "RATES_CONCEPTS".into(),
            },
            release_at: "2026-08-10T00:00:00Z".into(),
            source: "statistics".into(),
            view: "rates".into(),
            dimensions: vec![crate::model::CompiledStatisticalDimension {
                id: "REF_AREA".into(),
                label: "Reference area".into(),
                description: "Observation geography".into(),
                source_column: "ref_area".into(),
                data_type: StatisticalValueType::String,
                codelist: None,
                semantic_iri: "urn:concept:area".into(),
                classification: classification.clone(),
            }],
            time: crate::model::CompiledStatisticalTimeDimension {
                id: "TIME_PERIOD".into(),
                label: "Time period".into(),
                description: "Observation period".into(),
                source_column: "time_period".into(),
                semantic_iri: "urn:concept:time".into(),
                classification: classification.clone(),
            },
            measure: crate::model::CompiledStatisticalMeasure {
                id: "PARTICIPATION_RATE".into(),
                label: "Participation rate".into(),
                description: "Observation value".into(),
                source_column: "obs_value".into(),
                data_type: StatisticalValueType::Decimal,
                semantic_iri: "urn:concept:rate".into(),
                classification: classification.clone(),
            },
            attributes: vec![crate::model::CompiledStatisticalAttribute {
                id: "UNIT_MEASURE".into(),
                label: "Unit".into(),
                description: "Observation unit".into(),
                source_column: "unit_measure".into(),
                data_type: StatisticalValueType::String,
                codelist: None,
                source_required: true,
                semantic_iri: "urn:concept:unit".into(),
                classification,
            }],
            access: CompiledAccess::Public,
            allow_unfiltered: true,
            maximum_observations: 100,
            maximum_offset: 100,
            processing_handling: Handling::Public,
            disclosure_handling: Handling::Public,
            column_accounting: Vec::new(),
            processing_descriptions: Vec::new(),
        }
    }

    #[test]
    fn closed_negotiation_rejects_generic_xml() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/xml"));
        assert_eq!(
            negotiate_data(&headers),
            Err(ProblemCode::UnsupportedRepresentation)
        );
    }

    #[test]
    fn csv_quotes_delimiters_without_interpreting_values() {
        let mut bytes = Vec::new();
        write_csv_row(&mut bytes, &["=SUM(1,2)".into(), "quoted\"value".into()]).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "\"=SUM(1,2)\",\"quoted\"\"value\"\n"
        );
    }

    #[test]
    fn hierarchical_agency_has_schema_safe_message_metadata() {
        assert_eq!(SDMX_SENDER_ID, "REGISTRY_RELAY");
        assert_eq!(
            schema_safe_message_identifier("EXAMPLE.STAT", "LABOUR.FLOW", "1.0.0", "data"),
            "EXAMPLE_STAT_LABOUR_FLOW_1_0_0_data"
        );
    }

    #[test]
    fn dsd_json_and_csv_share_dimension_order_and_binding_version() {
        let dataflow = statistical_dataflow();
        let row = BTreeMap::from([
            ("ref_area".into(), SqlValue::String("AA".into())),
            ("time_period".into(), SqlValue::String("2026-Q1".into())),
            ("obs_value".into(), SqlValue::Number(12.5)),
            ("unit_measure".into(), SqlValue::String("PERCENT".into())),
        ]);

        let csv =
            String::from_utf8(serialize_data_csv(&dataflow, std::slice::from_ref(&row)).unwrap())
                .expect("CSV is UTF-8");
        assert_eq!(
            csv.lines().next(),
            Some(
                "STRUCTURE,STRUCTURE_ID,ACTION,REF_AREA,TIME_PERIOD,PARTICIPATION_RATE,UNIT_MEASURE"
            )
        );
        let (dimensions, _) = dimension_metadata(&dataflow, &[row]).expect("metadata serializes");
        assert_eq!(dimensions[0]["id"], "REF_AREA");
        assert_eq!(dimensions[0]["keyPosition"], 0);
        assert_eq!(dimensions[1]["id"], "TIME_PERIOD");
        assert_eq!(dimensions[1]["keyPosition"], 1);

        let dsd = data_structure(&dataflow);
        assert_eq!(dsd["version"], "2.3.4");
        assert_eq!(
            dsd.pointer("/dataStructureComponents/dimensionList/dimensions/0/id"),
            Some(&json!("REF_AREA"))
        );
        assert_eq!(
            dsd.pointer("/dataStructureComponents/dimensionList/timeDimension/position"),
            Some(&json!(1))
        );
        assert!(data_structure_urn(&dataflow).ends_with("RATES_DSD(2.3.4)"));
        assert!(concept_urn(&dataflow, "REF_AREA").contains("RATES_CONCEPTS(2.3.4)"));
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Closed SDMX REST read adapter over governed statistical datasets.
//!
//! This module owns only the HTTP security and release boundary. Query
//! semantics, source execution, and representation construction remain in
//! their respective closed modules.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, VARY};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, Uri};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_sqlite::{ErrorKind as SqliteErrorKind, Value as SqlValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::artifacts::ArtifactAccessBinding;
use crate::audit::{
    AuditContext, AuditOutcome, OperationSurface, PrincipalKind, QueryShape, RelayAudit,
    RowBoundaryKind,
};
use crate::auth::{
    bearer_token, Authorization, AuthorizationError, AuthorizationRefusalClass, Principal,
};
use crate::contract::Handling;
use crate::model::{
    CompiledAccess, CompiledRegistry, CompiledStatisticalDataset, RowAuthoritySource,
};
use crate::problem::{ProblemCode, ProblemCodeResponseExt, TraceContext};
use crate::sdmx::{
    parse_data_query, serialize_data_csv, serialize_data_json, DataQueryError,
    DimensionAtObservation, RepresentationError, StatisticalRow, StatisticalValue,
    DATA_CSV_MEDIA_TYPE, DATA_JSON_MEDIA_TYPE, STRUCTURE_JSON_MEDIA_TYPE,
};
use crate::server::{uri_within_bound, RelayService};
use crate::sqlite_runtime::{SourceRevision, SqliteRuntimeError};

#[derive(Debug, Deserialize)]
pub(crate) struct KeyedDataPath {
    context: String,
    agency: String,
    resource: String,
    version: String,
    key: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OmittedKeyDataPath {
    context: String,
    agency: String,
    resource: String,
    version: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StructurePath {
    artefact_type: String,
    agency: String,
    resource: String,
    version: String,
}

#[derive(Clone)]
struct StatisticalAccess {
    principal: Option<Principal>,
    authorization: Authorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataRepresentation {
    Json,
    Csv,
}

impl DataRepresentation {
    const fn media_type(self) -> &'static str {
        match self {
            Self::Json => DATA_JSON_MEDIA_TYPE,
            Self::Csv => DATA_CSV_MEDIA_TYPE,
        }
    }

    const fn wire_format(self) -> &'static str {
        match self {
            Self::Json => "sdmx-json",
            Self::Csv => "sdmx-csv",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StructureRouteKind {
    Dataflow,
    DataStructure,
}

impl StructureRouteKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "dataflow" => Some(Self::Dataflow),
            "datastructure" => Some(Self::DataStructure),
            _ => None,
        }
    }

    const fn operation_surface(self) -> OperationSurface {
        match self {
            Self::Dataflow => OperationSurface::SdmxDataflowStructure,
            Self::DataStructure => OperationSurface::SdmxDatastructureStructure,
        }
    }

    const fn artifact_suffix(self) -> &'static str {
        match self {
            Self::Dataflow => "dataflow",
            Self::DataStructure => "datastructure",
        }
    }

    const fn path_suffix(self) -> &'static str {
        match self {
            Self::Dataflow => "sdmx.dataflow.json",
            Self::DataStructure => "sdmx.datastructure.json",
        }
    }
}

pub(crate) async fn data_keyed(
    State(service): State<Arc<RelayService>>,
    Path(path): Path<KeyedDataPath>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    data_response(
        service,
        path.context,
        path.agency,
        path.resource,
        path.version,
        Some(path.key),
        headers,
        uri,
    )
    .await
}

pub(crate) async fn data_omitted_key(
    State(service): State<Arc<RelayService>>,
    Path(path): Path<OmittedKeyDataPath>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    data_response(
        service,
        path.context,
        path.agency,
        path.resource,
        path.version,
        None,
        headers,
        uri,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn data_response(
    service: Arc<RelayService>,
    context: String,
    agency: String,
    resource: String,
    version: String,
    key: Option<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    let principal = match authenticate_supplied(&service, &headers).await {
        Ok(value) => value,
        Err(()) => {
            return refuse_unknown(
                &service,
                PrincipalKind::Unknown,
                AuditOutcome::InvalidCredential,
                ProblemCode::InvalidCredential,
                &trace,
            )
            .await
        }
    };
    if context != "dataflow" {
        return refuse_unknown_sdmx(&service, principal.as_ref(), &trace).await;
    }
    let Some(dataset) = find_data_dataset(&service, &agency, &resource, &version) else {
        return refuse_unknown_sdmx(&service, principal.as_ref(), &trace).await;
    };
    let access = match authorize_dataset(
        &service,
        dataset,
        principal,
        OperationSurface::SdmxData,
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
            dataset,
            &access,
            OperationSurface::SdmxData,
            None,
            None,
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    let representation = match negotiate_data(&headers) {
        Some(value) => value,
        None => {
            return refuse_known(
                &service,
                dataset,
                &access,
                OperationSurface::SdmxData,
                None,
                None,
                AuditOutcome::InvalidRequest,
                ProblemCode::UnsupportedFormat,
                &trace,
            )
            .await
        }
    };
    let keyed = key.is_some();
    let query = match parse_data_query(dataset, key.as_deref(), uri.query()) {
        Ok(value) => value,
        Err(error) => {
            let code = match error {
                DataQueryError::Invalid => ProblemCode::AggregateDataInvalidRequest,
                DataQueryError::TooLarge => ProblemCode::AggregateDataTooLarge,
            };
            return refuse_known(
                &service,
                dataset,
                &access,
                OperationSurface::SdmxData,
                None,
                Some(representation.wire_format()),
                AuditOutcome::InvalidRequest,
                code,
                &trace,
            )
            .await;
        }
    };
    let shape = query_shape(keyed, query.dimension_at_observation);
    if quota_denied(&service, dataset) {
        return refuse_known(
            &service,
            dataset,
            &access,
            OperationSurface::SdmxData,
            Some(shape),
            Some(representation.wire_format()),
            AuditOutcome::RateLimited,
            ProblemCode::AggregateDataRateLimited,
            &trace,
        )
        .await;
    }

    let mut audit = audit_context(
        &service,
        dataset,
        Some(&access),
        OperationSurface::SdmxData,
        Some(shape),
        Some(representation.wire_format()),
        &trace,
    );
    if service.audit.attempt(&audit).await.is_err() {
        return ProblemCode::AuditUnavailable.response(&trace);
    }

    let limit = query.limit;
    let explicit_limit = query.explicit_limit;
    let dimension_at_observation = query.dimension_at_observation;
    let row_authority = access
        .authorization
        .row_authority
        .as_ref()
        .map(|authority| SqlValue::String(authority.value.clone()));
    let result = service
        .sqlite
        .execute_statistical(&dataset.operation_identifier(), query, row_authority)
        .await;
    let mut result = match result {
        Ok(value) => value,
        Err(error) => return source_failure(&service, &audit, error, &trace).await,
    };
    audit.source_revision = Some(result.source_revision.clone());
    let maximum = usize::try_from(limit).unwrap_or(usize::MAX);
    if result.rows.len() > maximum {
        if explicit_limit {
            result.rows.truncate(maximum);
        } else {
            return terminal_problem(
                &service,
                &audit,
                AuditOutcome::InvalidRequest,
                ProblemCode::AggregateDataTooLarge,
                &trace,
            )
            .await;
        }
    }
    if result.rows.is_empty() {
        return terminal_problem(
            &service,
            &audit,
            AuditOutcome::NotFound,
            ProblemCode::ResourceNotFound,
            &trace,
        )
        .await;
    }
    if !coded_source_values_are_governed(&service.registry, dataset, &result.rows) {
        return terminal_problem(
            &service,
            &audit,
            AuditOutcome::SourceFailed,
            ProblemCode::SourceUnavailable,
            &trace,
        )
        .await;
    }
    let bytes = match representation {
        DataRepresentation::Json => {
            serialize_data_json(dataset, &result.rows, dimension_at_observation)
        }
        DataRepresentation::Csv => serialize_data_csv(dataset, &result.rows),
    };
    let bytes = match bytes {
        Ok(value) => value,
        Err(error) => {
            return representation_failure(&service, &audit, error, &trace).await;
        }
    };
    release_bytes(
        &service,
        &audit,
        bytes,
        representation.media_type(),
        cacheable(dataset, &result.source_revision),
        &headers,
        &trace,
    )
    .await
}

pub(crate) async fn structure(
    State(service): State<Arc<RelayService>>,
    Path(path): Path<StructurePath>,
    headers: HeaderMap,
    uri: Uri,
) -> Response<Body> {
    let trace = TraceContext::from_headers(&headers);
    let principal = match authenticate_supplied(&service, &headers).await {
        Ok(value) => value,
        Err(()) => {
            return refuse_unknown(
                &service,
                PrincipalKind::Unknown,
                AuditOutcome::InvalidCredential,
                ProblemCode::InvalidCredential,
                &trace,
            )
            .await
        }
    };
    let Some(kind) = StructureRouteKind::parse(&path.artefact_type) else {
        return refuse_unknown_sdmx(&service, principal.as_ref(), &trace).await;
    };
    let Some(dataset) =
        find_structure_dataset(&service, kind, &path.agency, &path.resource, &path.version)
    else {
        return refuse_unknown_sdmx(&service, principal.as_ref(), &trace).await;
    };
    let access = match authorize_dataset(
        &service,
        dataset,
        principal,
        kind.operation_surface(),
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
            dataset,
            &access,
            kind.operation_surface(),
            None,
            None,
            AuditOutcome::InvalidRequest,
            ProblemCode::UriTooLong,
            &trace,
        )
        .await;
    }
    if !negotiate_structure(&headers) {
        return refuse_known(
            &service,
            dataset,
            &access,
            kind.operation_surface(),
            None,
            None,
            AuditOutcome::InvalidRequest,
            ProblemCode::UnsupportedFormat,
            &trace,
        )
        .await;
    }
    if !valid_structure_query(uri.query()) {
        return refuse_known(
            &service,
            dataset,
            &access,
            kind.operation_surface(),
            None,
            Some("sdmx-structure-json"),
            AuditOutcome::InvalidRequest,
            ProblemCode::AggregateDataInvalidRequest,
            &trace,
        )
        .await;
    }
    if quota_denied(&service, dataset) {
        return refuse_known(
            &service,
            dataset,
            &access,
            kind.operation_surface(),
            None,
            Some("sdmx-structure-json"),
            AuditOutcome::RateLimited,
            ProblemCode::AggregateDataRateLimited,
            &trace,
        )
        .await;
    }
    let audit = audit_context(
        &service,
        dataset,
        Some(&access),
        kind.operation_surface(),
        None,
        Some("sdmx-structure-json"),
        &trace,
    );
    if service.audit.attempt(&audit).await.is_err() {
        return ProblemCode::AuditUnavailable.response(&trace);
    }
    let artifact_id = format!("{}-sdmx-{}-structure", dataset.id, kind.artifact_suffix());
    let artifact_path = format!("artifacts/{}.{}", dataset.id, kind.path_suffix());
    let operation_identifier = dataset.operation_identifier();
    let artifact = service
        .artifacts
        .artifacts
        .iter()
        .find(|artifact| artifact.id == artifact_id);
    let Some(artifact) = artifact.filter(|artifact| {
        artifact.path == artifact_path
            && artifact.media_type == STRUCTURE_JSON_MEDIA_TYPE
            && artifact.operation_identifier.as_deref() == Some(operation_identifier.as_str())
            && artifact.access_binding == Some(ArtifactAccessBinding::FixedOperation)
            && artifact.sha256 == exact_digest(&artifact.content)
    }) else {
        return terminal_problem(
            &service,
            &audit,
            AuditOutcome::InternalFailed,
            ProblemCode::Internal,
            &trace,
        )
        .await;
    };
    let source_revision = service
        .sqlite
        .source_revision(&operation_identifier)
        .cloned();
    release_bytes(
        &service,
        &audit,
        artifact.content.clone(),
        STRUCTURE_JSON_MEDIA_TYPE,
        source_revision
            .as_ref()
            .is_some_and(|source| cacheable(dataset, source)),
        &headers,
        &trace,
    )
    .await
}

async fn authenticate_supplied(
    service: &RelayService,
    headers: &HeaderMap,
) -> Result<Option<Principal>, ()> {
    let token = bearer_token(headers).map_err(|_| ())?;
    let Some(token) = token else {
        return Ok(None);
    };
    let authenticator = service.authenticator.as_ref().ok_or(())?;
    authenticator
        .authenticate(token)
        .await
        .map(Some)
        .map_err(|_| ())
}

async fn authorize_dataset(
    service: &RelayService,
    dataset: &CompiledStatisticalDataset,
    principal: Option<Principal>,
    surface: OperationSurface,
    trace: &TraceContext,
) -> Result<StatisticalAccess, Response<Body>> {
    let authorization = match &service.authenticator {
        Some(authenticator) => authenticator.authorize(&dataset.access, principal.as_ref()),
        None => match dataset.access {
            CompiledAccess::Public => Ok(Authorization {
                row_authority: None,
                purpose: None,
            }),
            CompiledAccess::Protected { .. } => Err(AuthorizationError::AuthenticationRequired),
        },
    };
    match authorization {
        Ok(authorization) => Ok(StatisticalAccess {
            principal,
            authorization,
        }),
        Err(error) => {
            let (outcome, code) = match error.refusal_class() {
                AuthorizationRefusalClass::MissingCredential => (
                    AuditOutcome::MissingCredential,
                    ProblemCode::MissingCredential,
                ),
                AuthorizationRefusalClass::ConcealedScopeDenial => {
                    (AuditOutcome::NotFound, ProblemCode::ResourceNotFound)
                }
                AuthorizationRefusalClass::ExplicitDenial => {
                    (AuditOutcome::Denied, ProblemCode::AggregateDataDenied)
                }
            };
            let denied = StatisticalAccess {
                principal,
                authorization: Authorization {
                    row_authority: None,
                    purpose: None,
                },
            };
            Err(refuse_known(
                service, dataset, &denied, surface, None, None, outcome, code, trace,
            )
            .await)
        }
    }
}

fn find_data_dataset<'a>(
    service: &'a RelayService,
    agency: &str,
    dataflow: &str,
    version: &str,
) -> Option<&'a CompiledStatisticalDataset> {
    service
        .registry
        .statistical_datasets
        .iter()
        .find(|dataset| {
            dataset.sdmx.agency_id == agency
                && dataset.sdmx.dataflow_id == dataflow
                && dataset.sdmx.version == version
        })
}

fn find_structure_dataset<'a>(
    service: &'a RelayService,
    kind: StructureRouteKind,
    agency: &str,
    resource: &str,
    version: &str,
) -> Option<&'a CompiledStatisticalDataset> {
    service
        .registry
        .statistical_datasets
        .iter()
        .find(|dataset| {
            let expected = match kind {
                StructureRouteKind::Dataflow => &dataset.sdmx.dataflow_id,
                StructureRouteKind::DataStructure => &dataset.sdmx.data_structure_id,
            };
            dataset.sdmx.agency_id == agency
                && expected == resource
                && dataset.sdmx.version == version
        })
}

fn query_shape(keyed: bool, dimension: DimensionAtObservation) -> QueryShape {
    match (keyed, dimension) {
        (true, DimensionAtObservation::TimePeriod) => QueryShape::SdmxKeyedTimePeriod,
        (true, DimensionAtObservation::AllDimensions) => QueryShape::SdmxKeyedAllDimensions,
        (false, DimensionAtObservation::TimePeriod) => QueryShape::SdmxOmittedKeyTimePeriod,
        (false, DimensionAtObservation::AllDimensions) => QueryShape::SdmxOmittedKeyAllDimensions,
    }
}

fn quota_denied(service: &RelayService, dataset: &CompiledStatisticalDataset) -> bool {
    service
        .quota
        .as_ref()
        .is_some_and(|limiter| !limiter.admit(&dataset.operation_identifier()))
}

fn negotiate_data(headers: &HeaderMap) -> Option<DataRepresentation> {
    negotiate(
        headers,
        &[
            (DATA_JSON_MEDIA_TYPE, DataRepresentation::Json),
            (DATA_CSV_MEDIA_TYPE, DataRepresentation::Csv),
        ],
    )
}

fn negotiate_structure(headers: &HeaderMap) -> bool {
    negotiate(headers, &[(STRUCTURE_JSON_MEDIA_TYPE, ())]).is_some()
}

fn negotiate<T: Copy>(headers: &HeaderMap, offered: &[(&str, T)]) -> Option<T> {
    if headers.get_all(ACCEPT).iter().next().is_none() {
        return offered.first().map(|(_, representation)| *representation);
    }
    let mut ranges = Vec::new();
    for value in headers.get_all(ACCEPT) {
        let value = value.to_str().ok()?;
        for item in value.split(',') {
            ranges.push(parse_accept_item(item)?);
        }
    }

    let mut best: Option<(u16, T)> = None;
    for (media_type, representation) in offered {
        let (expected_media_type, expected_version) = split_media_type(media_type)?;
        let effective = ranges
            .iter()
            .filter_map(|range| {
                accept_specificity(range, expected_media_type, expected_version)
                    .map(|specificity| (specificity, range.quality))
            })
            .max_by_key(|(specificity, quality)| (*specificity, *quality));
        let Some((_, quality)) = effective else {
            continue;
        };
        if quality > 0 && best.is_none_or(|(best_quality, _)| quality > best_quality) {
            best = Some((quality, *representation));
        }
    }
    best.map(|(_, representation)| representation)
}

fn accept_specificity(
    range: &AcceptItem,
    expected_media_type: &str,
    expected_version: &str,
) -> Option<u8> {
    if range.media_type == "*/*" && range.version.is_none() {
        return Some(0);
    }
    if !range.media_type.eq_ignore_ascii_case(expected_media_type) {
        return None;
    }
    // A specific q=0 range is an exclusion for that SDMX media type even when
    // it names another version. A positive range must still opt into the exact
    // version Relay offers.
    (range.quality == 0 || range.version.as_deref() == Some(expected_version)).then_some(1)
}

struct AcceptItem {
    media_type: String,
    version: Option<String>,
    quality: u16,
}

fn parse_accept_item(value: &str) -> Option<AcceptItem> {
    let mut parts = value.trim().split(';');
    let media_type = parts.next()?.trim();
    if media_type.is_empty() || !media_type.contains('/') {
        return None;
    }
    let mut version = None;
    let mut quality = 1_000;
    let mut seen_quality = false;
    for parameter in parts {
        let (name, value) = parameter.trim().split_once('=')?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("version") {
            if version.replace(value.to_owned()).is_some() {
                return None;
            }
        } else if name.eq_ignore_ascii_case("q") {
            if seen_quality {
                return None;
            }
            quality = parse_quality(value)?;
            seen_quality = true;
        } else {
            return None;
        }
    }
    Some(AcceptItem {
        media_type: media_type.to_ascii_lowercase(),
        version,
        quality,
    })
}

fn split_media_type(value: &str) -> Option<(&str, &str)> {
    let (media_type, version) = value.split_once(";version=")?;
    Some((media_type, version))
}

fn parse_quality(value: &str) -> Option<u16> {
    if value == "1" || matches!(value, "1.0" | "1.00" | "1.000") {
        return Some(1_000);
    }
    if value == "0" {
        return Some(0);
    }
    let fraction = value.strip_prefix("0.")?;
    if fraction.is_empty()
        || fraction.len() > 3
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let parsed = fraction.parse::<u16>().ok()?;
    Some(match fraction.len() {
        1 => parsed * 100,
        2 => parsed * 10,
        3 => parsed,
        _ => return None,
    })
}

fn valid_structure_query(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return true;
    };
    if query.is_empty() {
        return true;
    }
    let values = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    matches!(values.as_slice(), [(name, value)] if name == "references" && value == "none")
}

fn audit_context(
    service: &RelayService,
    dataset: &CompiledStatisticalDataset,
    access: Option<&StatisticalAccess>,
    operation_surface: OperationSurface,
    query_shape: Option<QueryShape>,
    wire_format: Option<&str>,
    trace: &TraceContext,
) -> AuditContext {
    AuditContext {
        operation_id: RelayAudit::operation_id(),
        trace_id: trace.trace_id.clone(),
        registry_identifier: service.registry.registry_identifier.clone(),
        resource_identifier: Some(dataset.id.clone()),
        operation_identifier: Some(dataset.operation_identifier()),
        operation_surface,
        query_shape,
        access_rule_revision: Some(access_revision(&dataset.access)),
        purpose: access.and_then(|access| access.authorization.purpose.clone()),
        row_boundary_kind: row_boundary(&dataset.access),
        access_profile: None,
        disclosure_profile: None,
        wire_format: wire_format.map(str::to_owned),
        format_profile: None,
        processing_description_identifiers: processing_descriptions(dataset),
        selected_properties: selected_properties(dataset),
        processing_handling: Some(handling_label(dataset.processing_handling).into()),
        disclosure_handling: Some(handling_label(dataset.disclosure_handling).into()),
        transform_identifiers: Vec::new(),
        contract_revision: service.registry.contract_revision.clone(),
        source_revision: service
            .sqlite
            .source_revision(&dataset.operation_identifier())
            .cloned(),
        principal_kind: access.map_or(PrincipalKind::Unknown, |access| {
            principal_kind(access.principal.as_ref())
        }),
    }
}

fn unknown_audit_context(
    service: &RelayService,
    principal_kind: PrincipalKind,
    trace: &TraceContext,
) -> AuditContext {
    AuditContext {
        operation_id: RelayAudit::operation_id(),
        trace_id: trace.trace_id.clone(),
        registry_identifier: service.registry.registry_identifier.clone(),
        resource_identifier: None,
        operation_identifier: None,
        operation_surface: OperationSurface::Unknown,
        query_shape: None,
        access_rule_revision: None,
        purpose: None,
        row_boundary_kind: RowBoundaryKind::Unknown,
        access_profile: None,
        disclosure_profile: None,
        wire_format: None,
        format_profile: None,
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

fn principal_kind(principal: Option<&Principal>) -> PrincipalKind {
    if principal.is_some() {
        PrincipalKind::Authenticated
    } else {
        PrincipalKind::Anonymous
    }
}

fn access_revision(access: &CompiledAccess) -> String {
    let value = serde_json::to_value(access).expect("compiled statistical access serializes");
    let bytes = canonicalize_json(&value).expect("compiled statistical access canonicalizes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
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

fn processing_descriptions(dataset: &CompiledStatisticalDataset) -> Vec<String> {
    dataset
        .processing_descriptions
        .iter()
        .filter(|description| {
            description
                .operation_refs
                .iter()
                .any(|reference| reference == "statistics:read")
        })
        .map(|description| description.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn selected_properties(dataset: &CompiledStatisticalDataset) -> Vec<String> {
    dataset
        .dimensions
        .iter()
        .map(|component| component.id.clone())
        .chain(std::iter::once(dataset.time.id.clone()))
        .chain(std::iter::once(dataset.measure.id.clone()))
        .chain(
            dataset
                .attributes
                .iter()
                .map(|component| component.id.clone()),
        )
        .collect()
}

fn coded_source_values_are_governed(
    registry: &CompiledRegistry,
    dataset: &CompiledStatisticalDataset,
    rows: &[StatisticalRow],
) -> bool {
    dataset
        .dimensions
        .iter()
        .filter_map(|component| {
            component
                .codelist
                .as_deref()
                .map(|path| (component.source_column.as_str(), path, true))
        })
        .chain(dataset.attributes.iter().filter_map(|component| {
            component.codelist.as_deref().map(|path| {
                (
                    component.source_column.as_str(),
                    path,
                    component.source_required,
                )
            })
        }))
        .all(|(column, path, required)| {
            let Some(codelist) = registry.codelists.iter().find(|item| item.path == path) else {
                return false;
            };
            rows.iter().all(|row| match row.get(column) {
                Some(StatisticalValue::String(value)) => {
                    codelist.values.iter().any(|allowed| allowed == value)
                }
                Some(StatisticalValue::Null) => !required,
                Some(
                    StatisticalValue::Integer(_)
                    | StatisticalValue::Decimal(_)
                    | StatisticalValue::Boolean(_),
                )
                | None => false,
            })
        })
}

const fn handling_label(value: Handling) -> &'static str {
    match value {
        Handling::Public => "public",
        Handling::Internal => "internal",
        Handling::Confidential => "confidential",
        Handling::Restricted => "restricted",
    }
}

#[allow(clippy::too_many_arguments)]
async fn refuse_known(
    service: &RelayService,
    dataset: &CompiledStatisticalDataset,
    access: &StatisticalAccess,
    surface: OperationSurface,
    query_shape: Option<QueryShape>,
    wire_format: Option<&str>,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    let context = audit_context(
        service,
        dataset,
        Some(access),
        surface,
        query_shape,
        wire_format,
        trace,
    );
    if service.audit.refusal(&context, outcome).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

async fn refuse_unknown(
    service: &RelayService,
    principal_kind: PrincipalKind,
    outcome: AuditOutcome,
    code: ProblemCode,
    trace: &TraceContext,
) -> Response<Body> {
    let context = unknown_audit_context(service, principal_kind, trace);
    if service.audit.refusal(&context, outcome).await.is_err() {
        return ProblemCode::AuditUnavailable.response(trace);
    }
    code.response(trace)
}

async fn refuse_unknown_sdmx(
    service: &RelayService,
    principal: Option<&Principal>,
    trace: &TraceContext,
) -> Response<Body> {
    let protected = service
        .registry
        .statistical_datasets
        .iter()
        .any(|dataset| matches!(dataset.access, CompiledAccess::Protected { .. }));
    let (outcome, code) = if protected && principal.is_none() {
        (
            AuditOutcome::MissingCredential,
            ProblemCode::MissingCredential,
        )
    } else {
        (AuditOutcome::NotFound, ProblemCode::ResourceNotFound)
    };
    refuse_unknown(service, principal_kind(principal), outcome, code, trace).await
}

async fn representation_failure(
    service: &RelayService,
    audit: &AuditContext,
    error: RepresentationError,
    trace: &TraceContext,
) -> Response<Body> {
    let (outcome, code) = match error {
        RepresentationError::InvalidRows => {
            (AuditOutcome::SourceFailed, ProblemCode::SourceUnavailable)
        }
        RepresentationError::OutputTooLarge => (
            AuditOutcome::InvalidRequest,
            ProblemCode::AggregateDataTooLarge,
        ),
        RepresentationError::EmptyRows
        | RepresentationError::UnsupportedBinding
        | RepresentationError::Serialization => {
            (AuditOutcome::InternalFailed, ProblemCode::Internal)
        }
    };
    terminal_problem(service, audit, outcome, code, trace).await
}

async fn source_failure(
    service: &RelayService,
    audit: &AuditContext,
    error: SqliteRuntimeError,
    trace: &TraceContext,
) -> Response<Body> {
    let (outcome, code) = match error {
        SqliteRuntimeError::ResultTooLarge => (
            AuditOutcome::InvalidRequest,
            ProblemCode::AggregateDataTooLarge,
        ),
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
    terminal_problem(service, audit, outcome, code, trace).await
}

const fn sqlite_error_is_timeout(kind: SqliteErrorKind) -> bool {
    matches!(
        kind,
        SqliteErrorKind::Timeout | SqliteErrorKind::TimeBudgetExceeded
    )
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

fn cacheable(dataset: &CompiledStatisticalDataset, source: &SourceRevision) -> bool {
    matches!(dataset.access, CompiledAccess::Public)
        && matches!(source, SourceRevision::Snapshot(_))
}

async fn release_bytes(
    service: &RelayService,
    audit: &AuditContext,
    bytes: Vec<u8>,
    media_type: &'static str,
    cacheable: bool,
    headers: &HeaderMap,
    trace: &TraceContext,
) -> Response<Body> {
    let etag = cacheable.then(|| exact_etag(&bytes));
    if etag
        .as_deref()
        .is_some_and(|value| if_none_match(headers, value))
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
    bytes_response(bytes, media_type, cacheable, etag.as_deref(), trace)
}

fn bytes_response(
    bytes: Vec<u8>,
    media_type: &'static str,
    cacheable: bool,
    etag: Option<&str>,
    trace: &TraceContext,
) -> Response<Body> {
    let mut response = Response::new(Body::from(bytes));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(media_type));
    apply_cache_headers(response.headers_mut(), cacheable, etag);
    trace.apply(response.headers_mut());
    response
}

fn not_modified(etag: &str, trace: &TraceContext) -> Response<Body> {
    not_modified_response(etag, trace)
}

fn not_modified_response(etag: &str, trace: &TraceContext) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    apply_cache_headers(response.headers_mut(), true, Some(etag));
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
    if let Some(value) = etag.and_then(|value| HeaderValue::from_str(value).ok()) {
        headers.insert(ETAG, value);
    }
}

fn exact_etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::digest(bytes)))
}

fn exact_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
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

    #[test]
    fn negotiation_is_closed_versioned_and_quality_ordered() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "application/vnd.sdmx.data+csv;version=2.1.0;q=0.1, application/vnd.sdmx.data+json;version=2.1.0;q=1",
            ),
        );
        assert_eq!(negotiate_data(&headers), Some(DataRepresentation::Json));

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.sdmx.data+json;version=2.1.0;q=0"),
        );
        assert_eq!(negotiate_data(&headers), None);

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.sdmx.data+json"),
        );
        assert_eq!(negotiate_data(&headers), None);

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.sdmx.data+json;version=2.0.0;q=0, */*;q=1"),
        );
        assert_eq!(negotiate_data(&headers), Some(DataRepresentation::Csv));

        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "application/vnd.sdmx.structure+json;version=2.0.0;q=0, */*;q=1",
            ),
        );
        assert!(!negotiate_structure(&headers));
    }

    #[test]
    fn structure_query_accepts_only_absence_or_references_none() {
        assert!(valid_structure_query(None));
        assert!(valid_structure_query(Some("references=none")));
        assert!(!valid_structure_query(Some("references=all")));
        assert!(!valid_structure_query(Some(
            "references=none&references=none"
        )));
        assert!(!valid_structure_query(Some("detail=allstubs")));
    }
}

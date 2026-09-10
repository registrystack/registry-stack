//! Canonical, bounded client for Base Registry Engine discovery and record reads.
//!
//! Base Registry Engine and Relay share Registry Record semantics, but not routes,
//! queries, Problems, entity tags, or credential eligibility. This client keeps
//! those product contracts explicit while reusing only private transport
//! machinery.

use std::fmt;

use registry_platform_httpsec::{response_trace_id, ProblemDocument, TraceId};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, ETAG, IF_MATCH, LINK,
    LOCATION, VARY,
};
use reqwest::{Method, Response, StatusCode};
use serde_json::Value;
use uuid::Uuid;

use crate::query::{breg_encoded_query, MAX_BREG_REQUEST_URI_BYTES};
use crate::transport::{exact_media_type, Transport};
use crate::*;

const APPLICATION_JSON: &str = "application/json";
const ANY_MEDIA_TYPE: &str = "*/*";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: usize = 4 * 1024;
const MAXIMUM_LOCATION_BYTES: usize = 2_048;
const X_CONTENT_TYPE_OPTIONS: reqwest::header::HeaderName =
    reqwest::header::HeaderName::from_static("x-content-type-options");

/// Which slot route one attachment exchange uses.
#[derive(Clone, Copy)]
enum BRegAttachmentRoute {
    Download,
    Upload,
    Remove,
}

/// One explicitly initiated exchange with one Base Registry Engine deployment.
pub struct BaseRegistryClient {
    config: BaseRegistryClientConfig,
    transport: Transport,
}

impl BaseRegistryClient {
    pub fn new(config: BaseRegistryClientConfig) -> Result<Self, BaseRegistryClientError> {
        config.validate()?;
        let transport = Transport::new(&config)?;
        Ok(Self { config, transport })
    }

    /// Unauthenticated liveness probe. Configured bearer credentials are never
    /// acquired or sent.
    pub async fn health(&self) -> Result<BRegComplete<BRegProbeStatus>, BaseRegistryClientError> {
        self.probe(&["health"], "alive").await
    }

    /// Unauthenticated readiness probe. Configured bearer credentials are
    /// never acquired or sent.
    pub async fn ready(&self) -> Result<BRegComplete<BRegProbeStatus>, BaseRegistryClientError> {
        self.probe(&["ready"], "ready").await
    }

    /// Retrieve the caller-filtered OpenAPI document as inert bounded bytes.
    pub async fn openapi(
        &self,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        self.raw_document(&["openapi.json"], access_profile).await
    }

    /// Retrieve caller-filtered Registry metadata as inert bounded bytes.
    pub async fn registry_metadata(
        &self,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        self.raw_document(&["v1", "registry"], access_profile).await
    }

    /// Retrieve and strictly validate caller-filtered Registry Metadata v1.
    ///
    /// The returned metadata is bound to this client's exact service base.
    /// Parsing metadata bytes directly remains inert and cannot authorize a
    /// write through this client.
    pub async fn registry_contract(
        &self,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegMetadata>, BaseRegistryClientError> {
        let raw = self.registry_metadata(access_profile).await?;
        let value = BRegMetadata::from_slice(raw.value.as_bytes())
            .map_err(|_| {
                BaseRegistryClientError::protocol(
                    StatusCode::OK.as_u16(),
                    BRegProtocolFailure::Body,
                    Some(raw.metadata.trace_id().clone()),
                )
            })?
            .bind_source(self.source_binding());
        Ok(BRegComplete {
            value,
            metadata: raw.metadata,
        })
    }

    /// Retrieve one caller-filtered entity schema as inert bounded bytes.
    pub async fn entity_schema(
        &self,
        entity_identifier: &str,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_breg_identifier(
            entity_identifier,
            "the Base Registry Engine entity identifier is invalid",
        )?;
        self.raw_document(&["v1", "schemas", entity_identifier], access_profile)
            .await
    }

    /// Read one canonical UUID record as a Registry Record v1 single envelope.
    pub async fn get_record(
        &self,
        entity_route: &str,
        record_identifier: &str,
        options: &BRegRecordOptions,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        validate_record_uuid(record_identifier)?;
        let mut pairs = Vec::new();
        options.append_get_query(&mut pairs);
        crate::query::ensure_query_bound(&pairs)
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let format = options.format_value();
        let wire = self
            .get(
                &["v1", "records", entity_route, record_identifier],
                &pairs,
                format.media_type(),
                Credential::Optional,
                EntityTagExpectation::Required,
            )
            .await?;
        decode_breg_single(wire, format, self.deployment_prefix())
    }

    /// Retrieve the first page of one Base Registry Engine record collection.
    pub async fn list_records(
        &self,
        entity_route: &str,
        request: &BRegListRequest,
    ) -> Result<BRegComplete<BRegPage<RegistryRecordCollectionResponse>>, BaseRegistryClientError>
    {
        validate_entity_route(entity_route)?;
        let pairs = request
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        self.collection_page(
            entity_route,
            &pairs,
            request.record_options().format_value(),
            request.record_options().access_profile_value(),
            None,
        )
        .await
    }

    /// Advance exactly one page using an opaque BReg continuation.
    pub async fn continue_list(
        &self,
        continuation: &BRegContinuation,
    ) -> Result<BRegComplete<BRegPage<RegistryRecordCollectionResponse>>, BaseRegistryClientError>
    {
        let pairs = continuation
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        self.collection_page(
            continuation.route(),
            &pairs,
            continuation.format(),
            continuation.access_profile(),
            Some(continuation),
        )
        .await
    }

    /// Read one direct record as a native GeoJSON Feature.
    pub async fn get_geojson_record(
        &self,
        entity_route: &str,
        record_identifier: &str,
        options: &BRegGeoJsonOptions,
    ) -> Result<BRegComplete<BRegGeoJsonFeature>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        validate_record_uuid(record_identifier)?;
        let pairs = options
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let wire = self
            .get(
                &["v1", "records", entity_route, record_identifier],
                &pairs,
                GEOJSON_MEDIA_TYPE,
                Credential::Optional,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        decode_geojson_feature(wire)
    }

    /// Retrieve the first page of one direct native GeoJSON collection.
    pub async fn list_geojson_records(
        &self,
        entity_route: &str,
        request: &BRegGeoJsonListRequest,
    ) -> Result<BRegComplete<BRegGeoJsonPage>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let pairs = request
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        self.geojson_page(entity_route, &pairs, request.access_profile(), None)
            .await
    }

    /// Advance exactly one native GeoJSON page.
    pub async fn continue_geojson_list(
        &self,
        continuation: &BRegGeoJsonContinuation,
    ) -> Result<BRegComplete<BRegGeoJsonPage>, BaseRegistryClientError> {
        let pairs = continuation
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        self.geojson_page(
            continuation.route(),
            &pairs,
            continuation.access_profile(),
            Some(continuation),
        )
        .await
    }

    /// Retrieve the first page of the effective-time `:current` collection.
    pub async fn list_current_records(
        &self,
        entity_route: &str,
        request: &BRegCurrentListRequest,
    ) -> Result<BRegComplete<BRegCurrentPage>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let pairs = request
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let route = format!("{entity_route}:current");
        let complete = self
            .record_collection(&route, &pairs, request.format())
            .await?;
        let continuation = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegCurrentContinuation::try_from_parts(
                    entity_route,
                    cursor,
                    request.format(),
                    request.access_profile().map(str::to_owned),
                    &complete.value.meta,
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegCurrentPage {
                value: complete.value,
                continuation,
            },
            metadata: complete.metadata,
        })
    }

    /// Advance exactly one effective-time `:current` page.
    pub async fn continue_current_list(
        &self,
        continuation: &BRegCurrentContinuation,
    ) -> Result<BRegComplete<BRegCurrentPage>, BaseRegistryClientError> {
        let pairs = continuation
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let route = format!("{}:current", continuation.route());
        let complete = self
            .record_collection(&route, &pairs, continuation.format())
            .await?;
        if !continuation.matches_meta(&complete.value.meta) {
            return Err(body_error(&complete));
        }
        let next = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegCurrentContinuation::try_from_parts(
                    continuation.route(),
                    cursor,
                    continuation.format(),
                    continuation.access_profile().map(str::to_owned),
                    &complete.value.meta,
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegCurrentPage {
                value: complete.value,
                continuation: next,
            },
            metadata: complete.metadata,
        })
    }

    /// Retrieve the first page of one effective-time `:as-of` collection.
    pub async fn list_records_as_of(
        &self,
        entity_route: &str,
        request: &BRegAsOfListRequest,
    ) -> Result<BRegComplete<BRegAsOfPage>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let pairs = request
            .as_of_query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let route = format!("{entity_route}:as-of");
        let complete = self
            .record_collection(&route, &pairs, request.format())
            .await?;
        let continuation = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegAsOfContinuation::try_from_parts(
                    entity_route,
                    cursor,
                    request.format(),
                    request.access_profile().map(str::to_owned),
                    &complete.value.meta,
                    request.as_of(),
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegAsOfPage {
                value: complete.value,
                continuation,
            },
            metadata: complete.metadata,
        })
    }

    /// Advance exactly one effective-time `:as-of` page.
    pub async fn continue_as_of_list(
        &self,
        continuation: &BRegAsOfContinuation,
    ) -> Result<BRegComplete<BRegAsOfPage>, BaseRegistryClientError> {
        let pairs = continuation
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let route = format!("{}:as-of", continuation.route());
        let complete = self
            .record_collection(&route, &pairs, continuation.format())
            .await?;
        if !continuation.matches_meta(&complete.value.meta) {
            return Err(body_error(&complete));
        }
        let next = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegAsOfContinuation::try_from_parts(
                    continuation.route(),
                    cursor,
                    continuation.format(),
                    continuation.access_profile().map(str::to_owned),
                    &complete.value.meta,
                    continuation.as_of(),
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegAsOfPage {
                value: complete.value,
                continuation: next,
            },
            metadata: complete.metadata,
        })
    }

    /// Retrieve the first page of one retained `:snapshot` collection.
    pub async fn list_snapshot_records(
        &self,
        entity_route: &str,
        request: &BRegSnapshotListRequest,
    ) -> Result<BRegComplete<BRegSnapshotPage>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let pairs = request
            .snapshot_query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let route = format!("{entity_route}:snapshot");
        let complete = self
            .record_collection(&route, &pairs, request.format())
            .await?;
        let (snapshot, valid_at) = snapshot_extensions(&complete)?;
        if request
            .requested_snapshot()
            .is_some_and(|requested| requested != snapshot)
            || request.valid_at_value() != valid_at.as_deref()
        {
            return Err(body_error(&complete));
        }
        let continuation = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegSnapshotContinuation::try_from_parts(
                    entity_route,
                    cursor,
                    request.format(),
                    request.access_profile().map(str::to_owned),
                    &complete.value.meta,
                    &snapshot,
                    valid_at.as_deref(),
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegSnapshotPage {
                value: complete.value,
                snapshot,
                valid_at,
                continuation,
            },
            metadata: complete.metadata,
        })
    }

    /// Advance exactly one retained snapshot page.
    pub async fn continue_snapshot_list(
        &self,
        continuation: &BRegSnapshotContinuation,
    ) -> Result<BRegComplete<BRegSnapshotPage>, BaseRegistryClientError> {
        let pairs = continuation
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let route = format!("{}:snapshot", continuation.route());
        let complete = self
            .record_collection(&route, &pairs, continuation.format())
            .await?;
        if !continuation.matches_meta(&complete.value.meta) {
            return Err(body_error(&complete));
        }
        let (snapshot, valid_at) = snapshot_extensions(&complete)?;
        if snapshot != continuation.snapshot() || valid_at.as_deref() != continuation.valid_at() {
            return Err(body_error(&complete));
        }
        let next = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegSnapshotContinuation::try_from_parts(
                    continuation.route(),
                    cursor,
                    continuation.format(),
                    continuation.access_profile().map(str::to_owned),
                    &complete.value.meta,
                    &snapshot,
                    valid_at.as_deref(),
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegSnapshotPage {
                value: complete.value,
                snapshot,
                valid_at,
                continuation: next,
            },
            metadata: complete.metadata,
        })
    }

    /// Retrieve the first page of one configured relationship collection.
    pub async fn list_relationship_records(
        &self,
        entity_route: &str,
        record_identifier: &str,
        path_route: &str,
        request: &BRegRelationshipListRequest,
    ) -> Result<BRegComplete<BRegRelationshipPage>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        validate_record_uuid(record_identifier)?;
        validate_entity_route(path_route)?;
        let pairs = request
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let complete = self
            .record_collection_segments(
                &["v1", "records", entity_route, record_identifier, path_route],
                &pairs,
                request.format(),
            )
            .await?;
        let continuation = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegRelationshipContinuation::try_from_parts(
                    entity_route,
                    record_identifier,
                    path_route,
                    cursor,
                    request.format(),
                    request.access_profile().map(str::to_owned),
                    &complete.value.meta,
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegRelationshipPage {
                value: complete.value,
                continuation,
            },
            metadata: complete.metadata,
        })
    }

    /// Advance exactly one configured relationship page.
    pub async fn continue_relationship_list(
        &self,
        continuation: &BRegRelationshipContinuation,
    ) -> Result<BRegComplete<BRegRelationshipPage>, BaseRegistryClientError> {
        let pairs = continuation
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let complete = self
            .record_collection_segments(
                &[
                    "v1",
                    "records",
                    continuation.route(),
                    continuation.root_record_identifier(),
                    continuation.path_route(),
                ],
                &pairs,
                continuation.format(),
            )
            .await?;
        if !continuation.matches_meta(&complete.value.meta) {
            return Err(body_error(&complete));
        }
        let next = complete
            .value
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegRelationshipContinuation::try_from_parts(
                    continuation.route(),
                    continuation.root_record_identifier(),
                    continuation.path_route(),
                    cursor,
                    continuation.format(),
                    continuation.access_profile().map(str::to_owned),
                    &complete.value.meta,
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegRelationshipPage {
                value: complete.value,
                continuation: next,
            },
            metadata: complete.metadata,
        })
    }

    /// Resolve one compiled selector to exactly one Registry Record.
    pub async fn lookup_record(
        &self,
        entity_route: &str,
        request: &BRegLookupRequest,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let pairs = request
            .query_pairs()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let route = format!("{entity_route}:lookup");
        let url = self.url_with_query(&["v1", "records", &route], &pairs)?;
        let format = request.record_options().format_value();
        let mut builder = self
            .transport
            .http
            .request(Method::POST, url)
            .header(ACCEPT, format.media_type())
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(
                request
                    .body()
                    .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?,
            );
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        let wire = self
            .wire(
                response,
                format.media_type(),
                EntityTagExpectation::Forbidden,
            )
            .await?;
        decode_breg_single(wire, format, self.deployment_prefix())
    }

    /// Retrieve one bounded first page of record revisions as inert JSON bytes.
    /// This does not decode revision semantics or follow a continuation. The
    /// caller explicitly selects the history profile and owns presentation.
    pub async fn record_revisions(
        &self,
        entity_route: &str,
        record_identifier: &str,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        validate_record_uuid(record_identifier)?;
        self.raw_document(
            &[
                "v1",
                "records",
                entity_route,
                record_identifier,
                "revisions",
            ],
            access_profile,
        )
        .await
    }

    /// Retrieve one exact positive revision as a Registry Record single envelope.
    pub async fn get_record_revision(
        &self,
        entity_route: &str,
        record_identifier: &str,
        revision: u64,
        options: &BRegRecordOptions,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        validate_record_uuid(record_identifier)?;
        if revision == 0 || revision > i64::MAX as u64 {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine revision must be a positive signed 64-bit integer",
            ));
        }
        options
            .ensure_collection_compatible()
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let mut pairs = Vec::new();
        options.append_query(&mut pairs);
        crate::query::ensure_query_bound(&pairs)
            .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
        let revision = revision.to_string();
        let format = options.format_value();
        let wire = self
            .get(
                &[
                    "v1",
                    "records",
                    entity_route,
                    record_identifier,
                    "revisions",
                    &revision,
                ],
                &pairs,
                format.media_type(),
                Credential::Optional,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        let body = wire.body.clone();
        let media_type = wire.media_type.clone();
        let complete = decode_breg_single(wire, format, self.deployment_prefix())?;
        if complete.value.data.record_identifier != record_identifier
            || complete.value.data.revision_identifier != revision
        {
            return Err(body_error(&complete));
        }
        Ok(BRegComplete {
            value: BRegRawDocument::new(media_type, body),
            metadata: complete.metadata,
        })
    }

    /// Execute one metadata-bound direct Create without automatic retry.
    pub async fn create_record(
        &self,
        operation: &BRegCreateBinding,
        request: &BRegCreateRequest,
        idempotency_key: &BRegIdempotencyKey,
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        self.validate_create_binding(operation, request)?;
        if !request.matches_recovery_execution(operation, idempotency_key, format) {
            return Err(BaseRegistryClientError::invalid_request(
                "the recovered Base Registry Engine Create request does not match its original execution",
            ));
        }
        let segments = fixed_operation_segments(operation.path())?;
        let pairs = access_profile_query(Some(operation.access_profile()))?;
        let url = self.url_with_query(&segments, &pairs)?;
        let mut builder = self
            .transport
            .http
            .request(Method::POST, url)
            .header(ACCEPT, format.media_type())
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .header("idempotency-key", idempotency_key.as_str())
            .body(request.body().to_vec());
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        let wire = self
            .mutation_wire(
                response,
                StatusCode::CREATED,
                format.media_type(),
                LocationExpectation::Required,
            )
            .await?;
        let complete = decode_breg_single(wire, format, self.deployment_prefix())?;
        validate_mutation_record(
            &complete,
            StatusCode::CREATED,
            operation.registry_identifier(),
            operation.dataset_identifier(),
            operation.entity_identifier(),
        )?;
        let expected_location = format!(
            "{}{}/{}",
            self.deployment_prefix(),
            operation.path(),
            complete.value.data.record_identifier
        );
        if complete.metadata.location() != Some(expected_location.as_str()) {
            return Err(BaseRegistryClientError::protocol(
                StatusCode::CREATED.as_u16(),
                BRegProtocolFailure::Location,
                Some(complete.metadata.trace_id().clone()),
            ));
        }
        Ok(complete)
    }

    /// Execute one metadata-bound direct PATCH without automatic retry.
    pub async fn patch_record(
        &self,
        operation: &BRegPatchBinding,
        record_identifier: Uuid,
        etag: &BRegEtag,
        request: &BRegPatchRequest,
        idempotency_key: &BRegIdempotencyKey,
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        self.validate_patch_binding(operation, request)?;
        let path = operation.path_for_record(record_identifier);
        let segments = fixed_operation_segments(&path)?;
        let pairs = access_profile_query(Some(operation.access_profile()))?;
        let url = self.url_with_query(&segments, &pairs)?;
        let mut builder = self
            .transport
            .http
            .request(Method::PATCH, url)
            .header(ACCEPT, format.media_type())
            .header(CONTENT_TYPE, "application/json-patch+json")
            .header("idempotency-key", idempotency_key.as_str())
            .header(IF_MATCH, etag.as_str())
            .body(request.body().to_vec());
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        let wire = self
            .mutation_wire(
                response,
                StatusCode::OK,
                format.media_type(),
                LocationExpectation::Forbidden,
            )
            .await?;
        let complete = decode_breg_single(wire, format, self.deployment_prefix())?;
        validate_mutation_record(
            &complete,
            StatusCode::OK,
            operation.registry_identifier(),
            operation.dataset_identifier(),
            operation.entity_identifier(),
        )?;
        if complete.value.data.record_identifier != record_identifier.to_string() {
            return Err(body_failure(
                StatusCode::OK.as_u16(),
                complete.metadata.trace_id().clone(),
            ));
        }
        Ok(complete)
    }

    /// Replace one governed attachment slot with exact bytes.
    ///
    /// The upload is refused locally when the slot cannot accept it, so a
    /// refused upload never leaves the process.
    pub async fn upload_attachment(
        &self,
        slot: &BRegAttachmentSlot,
        record_identifier: Uuid,
        etag: &BRegEtag,
        upload: &BRegAttachmentUpload,
        idempotency_key: &BRegIdempotencyKey,
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        self.validate_attachment_slot(slot, BRegAttachmentRoute::Upload)?;
        if !upload.matches_slot(slot) {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine attachment upload was prepared for another slot",
            ));
        }
        let url = self.attachment_url(slot, record_identifier, None)?;
        let builder = self
            .transport
            .http
            .request(Method::PATCH, url)
            .header(ACCEPT, format.media_type())
            .header(CONTENT_TYPE, upload.content_type())
            .header("idempotency-key", idempotency_key.as_str())
            .header(IF_MATCH, etag.as_str())
            .body(upload.as_bytes().to_vec());
        self.attachment_mutation(builder, slot, record_identifier, format)
            .await
    }

    /// Read the exact bytes held in one governed attachment slot for one
    /// proposal version.
    ///
    /// The engine releases stored content only while the slot's verification
    /// status permits it, and the returned bytes are bounded by both the slot
    /// capacity and this client's configured response bound.
    pub async fn download_attachment(
        &self,
        slot: &BRegAttachmentSlot,
        record_identifier: Uuid,
        proposal_version: u32,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        self.validate_attachment_slot(slot, BRegAttachmentRoute::Download)?;
        if proposal_version == 0 {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine attachment proposal version must be positive",
            ));
        }
        let url = self.attachment_url(slot, record_identifier, Some(proposal_version))?;
        // The engine never negotiates a binary read: it answers with the exact
        // stored content type. Send the header explicitly rather than leaving
        // it to the HTTP library's default.
        let mut builder = self.transport.http.get(url).header(ACCEPT, ANY_MEDIA_TYPE);
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        self.attachment_wire(response, slot).await
    }

    /// Empty one governed attachment slot.
    pub async fn delete_attachment(
        &self,
        slot: &BRegAttachmentSlot,
        record_identifier: Uuid,
        etag: &BRegEtag,
        idempotency_key: &BRegIdempotencyKey,
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        self.validate_attachment_slot(slot, BRegAttachmentRoute::Remove)?;
        let url = self.attachment_url(slot, record_identifier, None)?;
        let builder = self
            .transport
            .http
            .request(Method::DELETE, url)
            .header(ACCEPT, format.media_type())
            .header("idempotency-key", idempotency_key.as_str())
            .header(IF_MATCH, etag.as_str());
        self.attachment_mutation(builder, slot, record_identifier, format)
            .await
    }

    /// Promote the actor actions advertised on one Registry Record against a
    /// caller-filtered lifecycle authority fetched by this client.
    pub fn lifecycle_actions(
        &self,
        authority: &BRegLifecycleAuthority,
        record: &RegistryRecordSingleResponse,
    ) -> Result<Vec<BRegLifecycleAction>, BRegLifecyclePromotionError> {
        if !authority.matches_source(&self.source_binding()) {
            return Err(BRegLifecyclePromotionError::Authority);
        }
        let request = BRegRequestMetadata::from_record(&record.data)
            .map_err(|_| BRegLifecyclePromotionError::Binding)?
            .ok_or(BRegLifecyclePromotionError::Binding)?;
        let record_binding = BRegLifecycleRecordBinding::from_record(&record.meta, &record.data)?;
        request.promote_actions(authority, &record_binding)
    }

    /// Execute one promoted change-request lifecycle action without automatic
    /// retry. A caller retry must reuse the same action and idempotency key.
    pub async fn execute_lifecycle_action(
        &self,
        action: &BRegLifecycleAction,
        idempotency_key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegLifecycleActionReceipt>, BaseRegistryClientError> {
        if !action.matches_source(&self.source_binding()) {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine lifecycle action belongs to another client source",
            ));
        }
        let url = self.url_for_lifecycle_action(action.href())?;
        let body = serde_json::to_vec(action.body()).map_err(|_| {
            BaseRegistryClientError::invalid_request(
                "the Base Registry Engine lifecycle action body is invalid",
            )
        })?;
        let mut builder = self
            .transport
            .http
            .request(Method::POST, url)
            .header(ACCEPT, APPLICATION_JSON)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .header("idempotency-key", idempotency_key.as_str())
            .header(IF_MATCH, action.if_match().as_str())
            .body(body);
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        let wire = self.lifecycle_wire(response).await?;
        let receipt = BRegLifecycleActionReceipt::from_slice(&wire.body)
            .map_err(|_| body_failure(wire.status, wire.metadata.trace_id().clone()))?;
        if !action.accepts_receipt(&receipt) {
            return Err(body_failure(wire.status, wire.metadata.trace_id().clone()));
        }
        Ok(BRegComplete {
            value: receipt,
            metadata: wire.metadata,
        })
    }

    pub(crate) fn validate_create_binding(
        &self,
        operation: &BRegCreateBinding,
        request: &BRegCreateRequest,
    ) -> Result<(), BaseRegistryClientError> {
        if !operation.matches_source(&self.source_binding())
            || !request.matches_recovery_binding(operation)
        {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine Create operation does not match its client or recovered request binding",
            ));
        }
        request
            .validate_fields(
                operation.writable_api_names(),
                operation.required_api_names(),
            )
            .map_err(|_| {
                BaseRegistryClientError::invalid_request(
                    "the Base Registry Engine Create request does not match the selected operation",
                )
            })
    }

    fn validate_attachment_slot(
        &self,
        slot: &BRegAttachmentSlot,
        route: BRegAttachmentRoute,
    ) -> Result<(), BaseRegistryClientError> {
        if !slot.matches_source(&self.source_binding()) {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine attachment slot belongs to another client source",
            ));
        }
        let advertised = match route {
            BRegAttachmentRoute::Download => slot.can_download(),
            BRegAttachmentRoute::Upload => slot.can_upload(),
            BRegAttachmentRoute::Remove => slot.can_remove(),
        };
        if !advertised {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine attachment slot does not advertise this route",
            ));
        }
        Ok(())
    }

    fn attachment_url(
        &self,
        slot: &BRegAttachmentSlot,
        record_identifier: Uuid,
        proposal_version: Option<u32>,
    ) -> Result<reqwest::Url, BaseRegistryClientError> {
        let path = slot.path_for_record(record_identifier);
        let segments = fixed_operation_segments(&path)?;
        let mut pairs = Vec::with_capacity(2);
        if let Some(version) = proposal_version {
            pairs.push(("proposalVersion".to_owned(), version.to_string()));
        }
        pairs.extend(access_profile_query(Some(slot.access_profile()))?);
        self.url_with_query(&segments, &pairs)
    }

    async fn attachment_mutation(
        &self,
        builder: reqwest::RequestBuilder,
        slot: &BRegAttachmentSlot,
        record_identifier: Uuid,
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        let builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        let wire = self
            .mutation_wire(
                response,
                StatusCode::OK,
                format.media_type(),
                LocationExpectation::Forbidden,
            )
            .await?;
        let complete = decode_breg_single(wire, format, self.deployment_prefix())?;
        validate_mutation_record(
            &complete,
            StatusCode::OK,
            slot.registry_identifier(),
            slot.dataset_identifier(),
            slot.entity_identifier(),
        )?;
        if complete.value.data.record_identifier != record_identifier.to_string() {
            return Err(body_failure(
                StatusCode::OK.as_u16(),
                complete.metadata.trace_id().clone(),
            ));
        }
        Ok(complete)
    }

    /// A binary read carries neither a record representation nor a validator:
    /// it is a governed byte stream with its own narrower cache policy.
    async fn attachment_wire(
        &self,
        response: Response,
        slot: &BRegAttachmentSlot,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        let status = response.status();
        if status != StatusCode::OK {
            if status.is_success() {
                return Err(BaseRegistryClientError::protocol(
                    status.as_u16(),
                    BRegProtocolFailure::Status,
                    breg_trace_id(status, response.headers()).ok(),
                ));
            }
            return Err(breg_problem(response, &self.transport).await);
        }
        let headers = response.headers().clone();
        let trace_id = breg_trace_id(status, &headers)?;
        validate_no_store(status, &headers, &trace_id)?;
        validate_exact_header(
            status,
            &headers,
            &VARY,
            "authorization",
            BRegProtocolFailure::CachePolicy,
            &trace_id,
        )?;
        validate_exact_header(
            status,
            &headers,
            &CONTENT_DISPOSITION,
            "attachment",
            BRegProtocolFailure::CachePolicy,
            &trace_id,
        )?;
        validate_exact_header(
            status,
            &headers,
            &X_CONTENT_TYPE_OPTIONS,
            "nosniff",
            BRegProtocolFailure::CachePolicy,
            &trace_id,
        )?;
        // A retained value may predate a narrower current upload policy, so
        // only the concrete media-type grammar is enforced here.
        let media_type = single_media_type(&headers)
            .filter(|value| valid_attachment_content_type(value))
            .ok_or_else(|| {
                BaseRegistryClientError::protocol(
                    status.as_u16(),
                    BRegProtocolFailure::MediaType,
                    Some(trace_id.clone()),
                )
            })?;
        if breg_response_etag(status, &headers, &trace_id)?.is_some() {
            return Err(etag_failure(status, trace_id));
        }
        if breg_response_link(status, &headers, &trace_id)?.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::ProfileLink,
                Some(trace_id),
            ));
        }
        if breg_response_location(status, &headers, &trace_id)?.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::Location,
                Some(trace_id),
            ));
        }
        let body = self.transport.read(response, slot.maximum_bytes()).await?;
        Ok(BRegComplete {
            value: BRegRawDocument::new(media_type, body),
            metadata: BRegResponseMetadata::new(trace_id, None),
        })
    }

    fn validate_patch_binding(
        &self,
        operation: &BRegPatchBinding,
        request: &BRegPatchRequest,
    ) -> Result<(), BaseRegistryClientError> {
        if !operation.matches_source(&self.source_binding()) {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine PATCH operation belongs to another client source",
            ));
        }
        request
            .validate_fields(
                operation.readable_api_names(),
                operation.writable_api_names(),
                operation.removable_api_names(),
            )
            .map_err(|_| {
                BaseRegistryClientError::invalid_request(
                    "the Base Registry Engine PATCH request does not match the selected operation",
                )
            })
    }

    pub(crate) fn source_binding(&self) -> String {
        self.transport.base_url.as_url().as_str().to_owned()
    }

    fn deployment_prefix(&self) -> &str {
        self.transport
            .base_url
            .as_url()
            .path()
            .trim_end_matches('/')
    }

    fn url_for_lifecycle_action(
        &self,
        href: &str,
    ) -> Result<reqwest::Url, BaseRegistryClientError> {
        let (path, query) = href.split_once('?').ok_or_else(|| {
            BaseRegistryClientError::invalid_request(
                "the Base Registry Engine lifecycle action href is invalid",
            )
        })?;
        let profile = query.strip_prefix("accessProfile=").ok_or_else(|| {
            BaseRegistryClientError::invalid_request(
                "the Base Registry Engine lifecycle action href is invalid",
            )
        })?;
        if !valid_access_profile_identifier(profile) || query.contains(['&', ';', '#']) {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine lifecycle action href is invalid",
            ));
        }
        let segments = fixed_operation_segments(path)?;
        let mut url = self.transport.url(&segments)?;
        url.set_query(Some(query));
        if url.as_str().len() > MAX_BREG_REQUEST_URI_BYTES {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine request URI exceeds the client bound",
            ));
        }
        Ok(url)
    }

    async fn probe(
        &self,
        segments: &[&str],
        expected_status: &str,
    ) -> Result<BRegComplete<BRegProbeStatus>, BaseRegistryClientError> {
        let wire = self
            .get(
                segments,
                &[],
                APPLICATION_JSON,
                Credential::None,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        let complete = decode_breg_json::<BRegProbeStatus>(wire)?;
        if complete.value.status != expected_status {
            return Err(BaseRegistryClientError::protocol(
                StatusCode::OK.as_u16(),
                BRegProtocolFailure::Body,
                Some(complete.metadata.trace_id().clone()),
            ));
        }
        Ok(complete)
    }

    async fn raw_document(
        &self,
        segments: &[&str],
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        let pairs = access_profile_query(access_profile)?;
        let wire = self
            .get(
                segments,
                &pairs,
                APPLICATION_JSON,
                Credential::Optional,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        Ok(BRegComplete {
            value: BRegRawDocument::new(wire.media_type, wire.body),
            metadata: wire.metadata,
        })
    }

    async fn collection_page(
        &self,
        entity_route: &str,
        pairs: &[(String, String)],
        format: BRegRecordFormat,
        access_profile: Option<&str>,
        expected: Option<&BRegContinuation>,
    ) -> Result<BRegComplete<BRegPage<RegistryRecordCollectionResponse>>, BaseRegistryClientError>
    {
        validate_entity_route(entity_route)?;
        let wire = self
            .get(
                &["v1", "records", entity_route],
                pairs,
                format.media_type(),
                Credential::Optional,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        let complete = decode_breg_collection(wire, format, self.deployment_prefix())?;
        if expected.is_some_and(|expected| !expected.matches_meta(&complete.value.meta)) {
            return Err(body_failure(
                StatusCode::OK.as_u16(),
                complete.metadata.trace_id().clone(),
            ));
        }
        let continuation = complete
            .value
            .page_info
            .next_cursor
            .as_ref()
            .map(|cursor| {
                BRegContinuation::try_from_parts(
                    entity_route,
                    cursor,
                    format,
                    access_profile.map(str::to_owned),
                    &complete.value.meta,
                )
            })
            .transpose()
            .map_err(|_| {
                BaseRegistryClientError::protocol(
                    StatusCode::OK.as_u16(),
                    BRegProtocolFailure::Body,
                    Some(complete.metadata.trace_id().clone()),
                )
            })?;
        Ok(BRegComplete {
            value: BRegPage {
                value: complete.value,
                continuation,
            },
            metadata: complete.metadata,
        })
    }

    async fn record_collection(
        &self,
        route: &str,
        pairs: &[(String, String)],
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordCollectionResponse>, BaseRegistryClientError> {
        self.record_collection_segments(&["v1", "records", route], pairs, format)
            .await
    }

    async fn record_collection_segments(
        &self,
        segments: &[&str],
        pairs: &[(String, String)],
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordCollectionResponse>, BaseRegistryClientError> {
        let wire = self
            .get(
                segments,
                pairs,
                format.media_type(),
                Credential::Optional,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        decode_breg_collection(wire, format, self.deployment_prefix())
    }

    async fn geojson_page(
        &self,
        entity_route: &str,
        pairs: &[(String, String)],
        access_profile: Option<&str>,
        _expected: Option<&BRegGeoJsonContinuation>,
    ) -> Result<BRegComplete<BRegGeoJsonPage>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let wire = self
            .get(
                &["v1", "records", entity_route],
                pairs,
                GEOJSON_MEDIA_TYPE,
                Credential::Optional,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        let complete = decode_geojson_collection(wire)?;
        let continuation = complete
            .value
            .registry
            .page_info
            .next_cursor
            .as_deref()
            .map(|cursor| {
                BRegGeoJsonContinuation::try_from_parts(
                    entity_route,
                    cursor,
                    access_profile.map(str::to_owned),
                )
            })
            .transpose()
            .map_err(|_| body_error(&complete))?;
        Ok(BRegComplete {
            value: BRegGeoJsonPage {
                value: complete.value,
                continuation,
            },
            metadata: complete.metadata,
        })
    }

    /// Execute one metadata-bound JSON POST without retry or link following.
    pub(crate) async fn execute_bound_json(
        &self,
        path: &str,
        access_profile: &str,
        body: Vec<u8>,
        idempotency_key: Option<&BRegIdempotencyKey>,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        let segments = bound_json_operation_segments(path)?;
        let pairs = access_profile_query(Some(access_profile))?;
        let url = self.url_with_query(&segments, &pairs)?;
        let mut builder = self
            .transport
            .http
            .request(Method::POST, url)
            .header(ACCEPT, APPLICATION_JSON)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(body);
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key.as_str());
        }
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        let wire = self.bound_json_wire(response).await?;
        crate::strict_json::from_slice(&wire.body)
            .map_err(|_| body_failure(wire.status, wire.metadata.trace_id().clone()))?;
        Ok(BRegComplete {
            value: BRegRawDocument::new(wire.media_type, wire.body),
            metadata: wire.metadata,
        })
    }

    /// Execute one metadata-bound tombstone and validate its returned record identity.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_tombstone(
        &self,
        path: &str,
        access_profile: &str,
        registry_identifier: &str,
        dataset_identifier: &str,
        entity_identifier: &str,
        record_identifier: Uuid,
        etag: &BRegEtag,
        idempotency_key: &BRegIdempotencyKey,
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        let segments = fixed_operation_segments(path)?;
        let pairs = access_profile_query(Some(access_profile))?;
        let url = self.url_with_query(&segments, &pairs)?;
        let mut builder = self
            .transport
            .http
            .request(Method::DELETE, url)
            .header(ACCEPT, format.media_type())
            .header("idempotency-key", idempotency_key.as_str())
            .header(IF_MATCH, etag.as_str());
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send(builder).await?;
        let wire = self
            .mutation_wire(
                response,
                StatusCode::OK,
                format.media_type(),
                LocationExpectation::Forbidden,
            )
            .await?;
        let complete = decode_breg_single(wire, format, self.deployment_prefix())?;
        validate_mutation_record(
            &complete,
            StatusCode::OK,
            registry_identifier,
            dataset_identifier,
            entity_identifier,
        )?;
        if complete.value.data.record_identifier != record_identifier.to_string() {
            return Err(body_error(&complete));
        }
        Ok(complete)
    }

    async fn get(
        &self,
        segments: &[&str],
        pairs: &[(String, String)],
        accept: &str,
        credential: Credential,
        etag: EntityTagExpectation,
    ) -> Result<BRegWire, BaseRegistryClientError> {
        let url = self.url_with_query(segments, pairs)?;
        let mut builder = self.transport.http.get(url).header(ACCEPT, accept);
        builder = self.authorize(builder, credential).await?;
        let response = self.transport.send(builder).await?;
        self.wire(response, accept, etag).await
    }

    async fn authorize(
        &self,
        mut builder: reqwest::RequestBuilder,
        credential: Credential,
    ) -> Result<reqwest::RequestBuilder, BaseRegistryClientError> {
        if matches!(credential, Credential::Optional) {
            if let Some(provider) = &self.config.token_provider {
                let token = provider.bearer_token().await?;
                builder = builder.header(AUTHORIZATION, token.authorization_header_value());
            }
        }
        Ok(builder)
    }

    fn url_with_query(
        &self,
        segments: &[&str],
        pairs: &[(String, String)],
    ) -> Result<reqwest::Url, BaseRegistryClientError> {
        let mut url = self.transport.url(segments)?;
        if !pairs.is_empty() {
            url.set_query(Some(&breg_encoded_query(pairs)));
        }
        if url.as_str().len() > MAX_BREG_REQUEST_URI_BYTES {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine request URI exceeds the client bound",
            ));
        }
        Ok(url)
    }

    async fn wire(
        &self,
        response: Response,
        expected_media: &str,
        etag_expectation: EntityTagExpectation,
    ) -> Result<BRegWire, BaseRegistryClientError> {
        self.wire_with_bound(
            response,
            expected_media,
            etag_expectation,
            self.config.max_response_bytes,
        )
        .await
    }

    async fn wire_with_bound(
        &self,
        response: Response,
        expected_media: &str,
        etag_expectation: EntityTagExpectation,
        maximum_bytes: u64,
    ) -> Result<BRegWire, BaseRegistryClientError> {
        let status = response.status();
        if status != StatusCode::OK {
            return Err(breg_problem(response, &self.transport).await);
        }
        let headers = response.headers().clone();
        let trace_id = breg_trace_id(status, &headers)?;
        if !exact_media_type(&headers, expected_media) {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let etag = breg_response_etag(status, &headers, &trace_id)?;
        if matches!(etag_expectation, EntityTagExpectation::Required) != etag.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::EntityTag,
                Some(trace_id),
            ));
        }
        let link = breg_response_link(status, &headers, &trace_id)?;
        if breg_response_location(status, &headers, &trace_id)?.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::Location,
                Some(trace_id),
            ));
        }
        let body = self
            .transport
            .read(response, self.config.max_response_bytes.min(maximum_bytes))
            .await?;
        Ok(BRegWire {
            body,
            metadata: BRegResponseMetadata::new(trace_id, etag),
            media_type: expected_media.to_owned(),
            link,
            status: status.as_u16(),
        })
    }

    async fn bound_json_wire(
        &self,
        response: Response,
    ) -> Result<BRegWire, BaseRegistryClientError> {
        let status = response.status();
        if status != StatusCode::OK {
            if status.is_success() {
                return Err(BaseRegistryClientError::protocol(
                    status.as_u16(),
                    BRegProtocolFailure::Status,
                    breg_trace_id(status, response.headers()).ok(),
                ));
            }
            return Err(breg_problem(response, &self.transport).await);
        }
        let headers = response.headers().clone();
        let trace_id = breg_trace_id(status, &headers)?;
        validate_mutation_cache_headers(status, &headers, &trace_id)?;
        if !exact_media_type(&headers, APPLICATION_JSON) {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        if breg_response_etag(status, &headers, &trace_id)?.is_some() {
            return Err(etag_failure(status, trace_id));
        }
        if breg_response_link(status, &headers, &trace_id)?.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::ProfileLink,
                Some(trace_id),
            ));
        }
        if breg_response_location(status, &headers, &trace_id)?.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::Location,
                Some(trace_id),
            ));
        }
        let body = self
            .transport
            .read(response, self.config.max_response_bytes)
            .await?;
        Ok(BRegWire {
            body,
            metadata: BRegResponseMetadata::new(trace_id, None),
            media_type: APPLICATION_JSON.to_owned(),
            link: None,
            status: status.as_u16(),
        })
    }

    async fn mutation_wire(
        &self,
        response: Response,
        expected_status: StatusCode,
        expected_media: &str,
        location_expectation: LocationExpectation,
    ) -> Result<BRegWire, BaseRegistryClientError> {
        let status = response.status();
        if status != expected_status {
            if status.is_success() {
                return Err(BaseRegistryClientError::protocol(
                    status.as_u16(),
                    BRegProtocolFailure::Status,
                    breg_trace_id(status, response.headers()).ok(),
                ));
            }
            return Err(breg_problem(response, &self.transport).await);
        }
        let headers = response.headers().clone();
        let trace_id = breg_trace_id(status, &headers)?;
        validate_mutation_cache_headers(status, &headers, &trace_id)?;
        if !exact_media_type(&headers, expected_media) {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let etag = breg_response_etag(status, &headers, &trace_id)?.ok_or_else(|| {
            BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::EntityTag,
                Some(trace_id.clone()),
            )
        })?;
        let link = breg_response_link(status, &headers, &trace_id)?;
        let location = breg_response_location(status, &headers, &trace_id)?;
        if matches!(location_expectation, LocationExpectation::Required) != location.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::Location,
                Some(trace_id),
            ));
        }
        let body = self
            .transport
            .read(response, self.config.max_response_bytes)
            .await?;
        let mut metadata = BRegResponseMetadata::new(trace_id, Some(etag));
        if let Some(location) = location {
            metadata = metadata.with_location(location);
        }
        Ok(BRegWire {
            body,
            metadata,
            media_type: expected_media.to_owned(),
            link,
            status: status.as_u16(),
        })
    }

    async fn lifecycle_wire(
        &self,
        response: Response,
    ) -> Result<BRegWire, BaseRegistryClientError> {
        let status = response.status();
        if status != StatusCode::OK {
            if status.is_success() {
                return Err(BaseRegistryClientError::protocol(
                    status.as_u16(),
                    BRegProtocolFailure::Status,
                    breg_trace_id(status, response.headers()).ok(),
                ));
            }
            return Err(breg_problem(response, &self.transport).await);
        }
        let headers = response.headers().clone();
        let trace_id = breg_trace_id(status, &headers)?;
        validate_mutation_cache_headers(status, &headers, &trace_id)?;
        if !exact_media_type(&headers, APPLICATION_JSON) {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        if breg_response_etag(status, &headers, &trace_id)?.is_some() {
            return Err(etag_failure(status, trace_id));
        }
        if breg_response_link(status, &headers, &trace_id)?.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::ProfileLink,
                Some(trace_id),
            ));
        }
        if breg_response_location(status, &headers, &trace_id)?.is_some() {
            return Err(BaseRegistryClientError::protocol(
                status.as_u16(),
                BRegProtocolFailure::Location,
                Some(trace_id),
            ));
        }
        let body = self
            .transport
            .read(response, self.config.max_response_bytes)
            .await?;
        Ok(BRegWire {
            body,
            metadata: BRegResponseMetadata::new(trace_id, None),
            media_type: APPLICATION_JSON.to_owned(),
            link: None,
            status: status.as_u16(),
        })
    }
}

impl fmt::Debug for BaseRegistryClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaseRegistryClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum Credential {
    None,
    Optional,
}

#[derive(Clone, Copy)]
enum EntityTagExpectation {
    Required,
    Forbidden,
}

#[derive(Clone, Copy)]
enum LocationExpectation {
    Required,
    Forbidden,
}

struct BRegWire {
    body: Vec<u8>,
    metadata: BRegResponseMetadata,
    media_type: String,
    link: Option<String>,
    status: u16,
}

fn decode_breg_json<T: serde::de::DeserializeOwned>(
    wire: BRegWire,
) -> Result<BRegComplete<T>, BaseRegistryClientError> {
    let status = wire.status;
    let value = serde_json::from_slice(&wire.body).map_err(|_| {
        BaseRegistryClientError::protocol(
            status,
            BRegProtocolFailure::Body,
            Some(wire.metadata.trace_id().clone()),
        )
    })?;
    Ok(BRegComplete {
        value,
        metadata: wire.metadata,
    })
}

fn decode_geojson_feature(
    wire: BRegWire,
) -> Result<BRegComplete<BRegGeoJsonFeature>, BaseRegistryClientError> {
    let status = wire.status;
    let trace_id = wire.metadata.trace_id().clone();
    if wire.link.is_some() {
        return Err(BaseRegistryClientError::protocol(
            status,
            BRegProtocolFailure::ProfileLink,
            Some(trace_id),
        ));
    }
    let value = crate::strict_json::from_slice(&wire.body)
        .map_err(|_| body_failure(status, trace_id.clone()))?;
    let value = crate::geojson::decode_feature(value)
        .map_err(|_| body_failure(status, trace_id.clone()))?;
    Ok(BRegComplete {
        value,
        metadata: wire.metadata,
    })
}

fn decode_geojson_collection(
    wire: BRegWire,
) -> Result<BRegComplete<BRegGeoJsonFeatureCollection>, BaseRegistryClientError> {
    let status = wire.status;
    let trace_id = wire.metadata.trace_id().clone();
    if wire.link.is_some() {
        return Err(BaseRegistryClientError::protocol(
            status,
            BRegProtocolFailure::ProfileLink,
            Some(trace_id),
        ));
    }
    let value = crate::strict_json::from_slice(&wire.body)
        .map_err(|_| body_failure(status, trace_id.clone()))?;
    let value = crate::geojson::decode_collection(value)
        .map_err(|_| body_failure(status, trace_id.clone()))?;
    Ok(BRegComplete {
        value,
        metadata: wire.metadata,
    })
}

fn snapshot_extensions(
    complete: &BRegComplete<RegistryRecordCollectionResponse>,
) -> Result<(String, Option<String>), BaseRegistryClientError> {
    let snapshot = complete
        .value
        .extensions
        .get("snapshot")
        .and_then(Value::as_str)
        .filter(|value| valid_snapshot_reference(value))
        .map(str::to_owned)
        .ok_or_else(|| body_error(complete))?;
    let valid_at = match complete.value.extensions.get("validAt") {
        None => None,
        Some(Value::String(value)) => Some(
            crate::read::normalize_snapshot_valid_at(value).map_err(|_| body_error(complete))?,
        ),
        Some(_) => return Err(body_error(complete)),
    };
    if complete
        .value
        .extensions
        .iter()
        .any(|(name, value)| match name.as_str() {
            "snapshot" | "validAt" => false,
            "count" => value.as_u64().is_none_or(|count| count > i64::MAX as u64),
            _ => true,
        })
    {
        return Err(body_error(complete));
    }
    Ok((snapshot, valid_at))
}

fn body_error<T>(complete: &BRegComplete<T>) -> BaseRegistryClientError {
    body_failure(
        StatusCode::OK.as_u16(),
        complete.metadata.trace_id().clone(),
    )
}

fn decode_breg_single(
    wire: BRegWire,
    format: BRegRecordFormat,
    deployment_prefix: &str,
) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
    let status = wire.status;
    let trace_id = wire.metadata.trace_id().clone();
    let link = wire.link.clone();
    let value = decode_registry_record(&wire.body, format, status, &trace_id)?;
    let RegistryRecordResponse::Single(value) = value else {
        return Err(body_failure(status, trace_id));
    };
    validate_breg_records(std::slice::from_ref(&value.data), status, &trace_id)?;
    validate_profile_link(
        link.as_deref(),
        &value.meta.entity_type_identifier,
        deployment_prefix,
        status,
        &trace_id,
    )?;
    Ok(BRegComplete {
        value,
        metadata: wire.metadata,
    })
}

fn decode_breg_collection(
    wire: BRegWire,
    format: BRegRecordFormat,
    deployment_prefix: &str,
) -> Result<BRegComplete<RegistryRecordCollectionResponse>, BaseRegistryClientError> {
    let status = wire.status;
    let trace_id = wire.metadata.trace_id().clone();
    let link = wire.link.clone();
    let value = decode_registry_record(&wire.body, format, status, &trace_id)?;
    let RegistryRecordResponse::Collection(value) = value else {
        return Err(body_failure(status, trace_id));
    };
    validate_breg_records(&value.items, status, &trace_id)?;
    validate_profile_link(
        link.as_deref(),
        &value.meta.entity_type_identifier,
        deployment_prefix,
        status,
        &trace_id,
    )?;
    Ok(BRegComplete {
        value,
        metadata: wire.metadata,
    })
}

fn decode_registry_record(
    body: &[u8],
    format: BRegRecordFormat,
    status: u16,
    trace_id: &TraceId,
) -> Result<RegistryRecordResponse, BaseRegistryClientError> {
    let representation = match format {
        BRegRecordFormat::Json => RegistryRecordRepresentation::Json,
        BRegRecordFormat::JsonLd => RegistryRecordRepresentation::JsonLdSharedContext,
    };
    let value = crate::strict_json::from_slice(body).map_err(|_| {
        BaseRegistryClientError::protocol(status, BRegProtocolFailure::Body, Some(trace_id.clone()))
    })?;
    RegistryRecordResponse::from_value(value, representation).map_err(|_| {
        BaseRegistryClientError::protocol(status, BRegProtocolFailure::Body, Some(trace_id.clone()))
    })
}

fn validate_breg_records(
    records: &[RegistryRecord],
    status: u16,
    trace_id: &TraceId,
) -> Result<(), BaseRegistryClientError> {
    if records.iter().any(|record| {
        !canonical_uuid(&record.record_identifier)
            || !canonical_positive_revision(&record.revision_identifier)
    }) {
        return Err(body_failure(status, trace_id.clone()));
    }
    Ok(())
}

fn validate_profile_link(
    actual: Option<&str>,
    entity_identifier: &str,
    deployment_prefix: &str,
    status: u16,
    trace_id: &TraceId,
) -> Result<(), BaseRegistryClientError> {
    if !valid_breg_identifier(entity_identifier) {
        return Err(body_failure(status, trace_id.clone()));
    }
    let expected = format!(
        "<{REGISTRY_RECORD_PROFILE_IDENTIFIER}>; rel=\"profile\", <{deployment_prefix}/v1/schemas/{entity_identifier}>; rel=\"describedby\""
    );
    if actual != Some(expected.as_str()) {
        return Err(BaseRegistryClientError::protocol(
            status,
            BRegProtocolFailure::ProfileLink,
            Some(trace_id.clone()),
        ));
    }
    Ok(())
}

fn access_profile_query(
    access_profile: Option<&str>,
) -> Result<Vec<(String, String)>, BaseRegistryClientError> {
    let Some(access_profile) = access_profile else {
        return Ok(Vec::new());
    };
    let options = BRegRecordOptions::default()
        .access_profile(access_profile)
        .map_err(|error| BaseRegistryClientError::invalid_request(error.reason()))?;
    let mut pairs = Vec::with_capacity(1);
    options.append_query(&mut pairs);
    Ok(pairs)
}

fn validate_entity_route(value: &str) -> Result<(), BaseRegistryClientError> {
    validate_breg_identifier(value, "the Base Registry Engine entity route is invalid")
}

fn validate_breg_identifier(
    value: &str,
    reason: &'static str,
) -> Result<(), BaseRegistryClientError> {
    if !valid_breg_identifier(value) {
        return Err(BaseRegistryClientError::invalid_request(reason));
    }
    Ok(())
}

fn valid_breg_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 64
        && first.is_ascii_lowercase()
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_access_profile_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 128
        && first.is_ascii_lowercase()
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn validate_record_uuid(value: &str) -> Result<(), BaseRegistryClientError> {
    if !canonical_uuid(value) {
        return Err(BaseRegistryClientError::invalid_request(
            "the Base Registry Engine record identifier must be a canonical lowercase UUID",
        ));
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

fn canonical_positive_revision(value: &str) -> bool {
    value
        .parse::<i64>()
        .ok()
        .is_some_and(|revision| revision > 0 && revision.to_string() == value)
}

fn single_media_type(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().map(ToOwned::to_owned),
        _ => None,
    }
}

fn breg_trace_id(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<TraceId, BaseRegistryClientError> {
    response_trace_id(headers).map_err(|_| {
        BaseRegistryClientError::protocol(status.as_u16(), BRegProtocolFailure::TraceContext, None)
    })
}

fn breg_response_etag(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    trace_id: &TraceId,
) -> Result<Option<BRegEtag>, BaseRegistryClientError> {
    let mut values = headers.get_all(ETAG).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(etag_failure(status, trace_id.clone()));
    }
    let value = value
        .to_str()
        .map_err(|_| etag_failure(status, trace_id.clone()))?;
    BRegEtag::parse(value)
        .map(Some)
        .map_err(|_| etag_failure(status, trace_id.clone()))
}

fn breg_response_link(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    trace_id: &TraceId,
) -> Result<Option<String>, BaseRegistryClientError> {
    let mut values = headers.get_all(LINK).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(BaseRegistryClientError::protocol(
            status.as_u16(),
            BRegProtocolFailure::ProfileLink,
            Some(trace_id.clone()),
        ));
    }
    value.to_str().map(str::to_owned).map(Some).map_err(|_| {
        BaseRegistryClientError::protocol(
            status.as_u16(),
            BRegProtocolFailure::ProfileLink,
            Some(trace_id.clone()),
        )
    })
}

fn fixed_operation_segments(path: &str) -> Result<Vec<&str>, BaseRegistryClientError> {
    if path.len() > MAXIMUM_LOCATION_BYTES
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['%', '?', '#', '\\'])
    {
        return Err(BaseRegistryClientError::invalid_request(
            "the selected Base Registry Engine operation path is invalid",
        ));
    }
    let segments = path[1..].split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || segments.iter().any(|segment| {
            segment.is_empty()
                || *segment == "."
                || *segment == ".."
                || segment.len() > 128
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
        })
    {
        return Err(BaseRegistryClientError::invalid_request(
            "the selected Base Registry Engine operation path is invalid",
        ));
    }
    Ok(segments)
}

fn bound_json_operation_segments(path: &str) -> Result<Vec<&str>, BaseRegistryClientError> {
    if !path.ends_with(":batch") {
        return fixed_operation_segments(path);
    }
    if path.len() > MAXIMUM_LOCATION_BYTES
        || !path.starts_with("/v1/records/")
        || path.contains(['%', '?', '#', '\\'])
    {
        return Err(BaseRegistryClientError::invalid_request(
            "the selected Base Registry Engine operation path is invalid",
        ));
    }
    let segments = path[1..].split('/').collect::<Vec<_>>();
    let exact_batch = matches!(segments.as_slice(), ["v1", "records", route]
        if route.strip_suffix(":batch").is_some_and(valid_operation_segment));
    if !exact_batch {
        return Err(BaseRegistryClientError::invalid_request(
            "the selected Base Registry Engine operation path is invalid",
        ));
    }
    Ok(segments)
}

fn valid_operation_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && segment.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn validate_mutation_record(
    complete: &BRegComplete<RegistryRecordSingleResponse>,
    status: StatusCode,
    expected_registry: &str,
    expected_dataset: &str,
    expected_entity: &str,
) -> Result<(), BaseRegistryClientError> {
    let value = &complete.value;
    let record = &value.data;
    let exact_snapshot = record.extensions.len() == 1
        && record
            .extensions
            .get("snapshot")
            .and_then(serde_json::Value::as_str)
            .is_some_and(valid_snapshot_reference);
    if value.meta.registry_identifier != expected_registry
        || value.meta.dataset_identifier != expected_dataset
        || value.meta.entity_type_identifier != expected_entity
        || !value.extensions.is_empty()
        || !value.meta.extensions.is_empty()
        || !exact_snapshot
    {
        return Err(body_failure(
            status.as_u16(),
            complete.metadata.trace_id().clone(),
        ));
    }
    Ok(())
}

fn valid_snapshot_reference(value: &str) -> bool {
    value.strip_prefix("breg1_").is_some_and(canonical_uuid)
}

fn validate_mutation_cache_headers(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    trace_id: &TraceId,
) -> Result<(), BaseRegistryClientError> {
    validate_no_store(status, headers, trace_id)?;
    validate_exact_header(
        status,
        headers,
        &VARY,
        "authorization, accept",
        BRegProtocolFailure::CachePolicy,
        trace_id,
    )
}

fn validate_no_store(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    trace_id: &TraceId,
) -> Result<(), BaseRegistryClientError> {
    validate_exact_header(
        status,
        headers,
        &CACHE_CONTROL,
        "no-store",
        BRegProtocolFailure::CachePolicy,
        trace_id,
    )
}

fn validate_exact_header(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    name: &reqwest::header::HeaderName,
    expected: &str,
    failure: BRegProtocolFailure,
    trace_id: &TraceId,
) -> Result<(), BaseRegistryClientError> {
    let mut values = headers.get_all(name).iter();
    let actual = values.next().and_then(|value| value.to_str().ok());
    if actual != Some(expected) || values.next().is_some() {
        return Err(BaseRegistryClientError::protocol(
            status.as_u16(),
            failure,
            Some(trace_id.clone()),
        ));
    }
    Ok(())
}

fn breg_response_location(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    trace_id: &TraceId,
) -> Result<Option<String>, BaseRegistryClientError> {
    let mut values = headers.get_all(LOCATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(BaseRegistryClientError::protocol(
            status.as_u16(),
            BRegProtocolFailure::Location,
            Some(trace_id.clone()),
        ));
    }
    let value = value.to_str().map_err(|_| {
        BaseRegistryClientError::protocol(
            status.as_u16(),
            BRegProtocolFailure::Location,
            Some(trace_id.clone()),
        )
    })?;
    fixed_operation_segments(value).map_err(|_| {
        BaseRegistryClientError::protocol(
            status.as_u16(),
            BRegProtocolFailure::Location,
            Some(trace_id.clone()),
        )
    })?;
    Ok(Some(value.to_owned()))
}

async fn breg_problem(response: Response, transport: &Transport) -> BaseRegistryClientError {
    let status = response.status();
    let headers = response.headers().clone();
    let trace_id = match breg_trace_id(status, &headers) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if let Err(error) = validate_no_store(status, &headers, &trace_id) {
        return error;
    }
    if !exact_media_type(&headers, PROBLEM_MEDIA_TYPE) {
        return BaseRegistryClientError::protocol(
            status.as_u16(),
            BRegProtocolFailure::MediaType,
            Some(trace_id),
        );
    }
    let body = match transport.read(response, MAXIMUM_PROBLEM_BYTES as u64).await {
        Ok(value) => value,
        Err(error) => return error,
    };
    let (document, extensions) = match parse_breg_problem(&body) {
        Ok(value) => value,
        Err(_) => return problem_failure(status, trace_id),
    };
    let code = BRegProblemCode::ALL.into_iter().find(|candidate| {
        document.code == candidate.code()
            && document.status == candidate.status()
            && document.title == candidate.title()
            && candidate.accepts_detail(&document.detail)
            && document.type_uri == candidate.type_uri()
    });
    let Some(code) = code else {
        return problem_failure(status, trace_id);
    };
    if code.status() != status.as_u16()
        || document.trace_id != trace_id
        || (extensions.declared_field && code != BRegProblemCode::MutationConflict)
        || extensions
            .field_path
            .is_some_and(|path| !path.permits(code))
        || extensions.refusal_code.is_some() != (code == BRegProblemCode::ActionRefused)
    {
        return problem_failure(status, trace_id);
    }
    BaseRegistryClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id,
        refusal_code: extensions.refusal_code,
    }
}

/// The closed forms a Base Registry Engine problem location takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BRegProblemPath {
    EvidenceAlias,
    ActionInputField,
    ActionRequest,
}

impl BRegProblemPath {
    fn permits(self, code: BRegProblemCode) -> bool {
        match self {
            Self::EvidenceAlias => code == BRegProblemCode::ActionEvidenceFailed,
            Self::ActionInputField => matches!(
                code,
                BRegProblemCode::ActionRefused | BRegProblemCode::RequestInvalid
            ),
            Self::ActionRequest => code == BRegProblemCode::RequestInvalid,
        }
    }
}

/// The BReg-owned members of one problem document, checked before the platform
/// parser reads the exact six common members.
struct BRegProblemExtensions {
    declared_field: bool,
    field_path: Option<BRegProblemPath>,
    refusal_code: Option<BRegRefusalCode>,
}

/// BReg owns paired field locations, problem locations, and the declared code an
/// immediate-action refusal names; the platform parser continues to own the
/// exact six common members. Locations are checked and discarded, never
/// retained as response-authored error text.
fn parse_breg_problem(body: &[u8]) -> Result<(ProblemDocument, BRegProblemExtensions), ()> {
    if body.is_empty() || body.len() > MAXIMUM_PROBLEM_BYTES {
        return Err(());
    }
    let serde_json::Value::Object(mut object) = crate::strict_json::from_slice(body)? else {
        return Err(());
    };
    let declared_field = match (object.remove("entityId"), object.remove("fieldId")) {
        (None, None) => false,
        (Some(serde_json::Value::String(entity)), Some(serde_json::Value::String(field)))
            if [&entity, &field].into_iter().all(|id| {
                !id.is_empty() && id.chars().count() <= 128 && !id.chars().any(char::is_control)
            }) =>
        {
            true
        }
        _ => return Err(()),
    };
    let field_path = match object.remove("fieldPath") {
        None => None,
        Some(serde_json::Value::String(path)) => Some(breg_problem_path(&path).ok_or(())?),
        _ => return Err(()),
    };
    let refusal_code = match object.remove("refusalCode") {
        None => None,
        Some(serde_json::Value::String(code)) => Some(BRegRefusalCode::parse(&code).ok_or(())?),
        _ => return Err(()),
    };
    let common = serde_json::to_vec(&object).map_err(|_| ())?;
    let document = ProblemDocument::parse_exact(&common, MAXIMUM_PROBLEM_BYTES).map_err(|_| ())?;
    Ok((
        document,
        BRegProblemExtensions {
            declared_field,
            field_path,
            refusal_code,
        },
    ))
}

fn breg_problem_path(path: &str) -> Option<BRegProblemPath> {
    if valid_evidence_problem_path(path) {
        return Some(BRegProblemPath::EvidenceAlias);
    }
    if valid_action_input_problem_path(path) {
        return Some(BRegProblemPath::ActionInputField);
    }
    valid_action_request_problem_path(path).then_some(BRegProblemPath::ActionRequest)
}

fn valid_evidence_problem_path(path: &str) -> bool {
    let Some(alias) = path.strip_prefix("/evidence/") else {
        return false;
    };
    let mut bytes = alias.bytes();
    alias.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// An action input is located by its public API name, which the package
/// declares as a bounded lower camelCase identifier.
fn valid_action_input_problem_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/input/") else {
        return false;
    };
    let mut bytes = name.bytes();
    name.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_alphanumeric())
}

fn valid_action_request_problem_path(path: &str) -> bool {
    if matches!(path, "" | "/input" | "/preconditions") {
        return true;
    }
    let Some(remainder) = path.strip_prefix("/preconditions/") else {
        return false;
    };
    let mut segments = remainder.split('/');
    let Some(name) = segments.next() else {
        return false;
    };
    let suffix = segments.next();
    segments.next().is_none()
        && suffix.is_none_or(|value| value == "ifMatch")
        && valid_api_problem_segment(name)
}

fn valid_api_problem_segment(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_alphanumeric())
}

fn body_failure(status: u16, trace_id: TraceId) -> BaseRegistryClientError {
    BaseRegistryClientError::protocol(status, BRegProtocolFailure::Body, Some(trace_id))
}

fn etag_failure(status: StatusCode, trace_id: TraceId) -> BaseRegistryClientError {
    BaseRegistryClientError::protocol(
        status.as_u16(),
        BRegProtocolFailure::EntityTag,
        Some(trace_id),
    )
}

fn problem_failure(status: StatusCode, trace_id: TraceId) -> BaseRegistryClientError {
    BaseRegistryClientError::protocol(
        status.as_u16(),
        BRegProtocolFailure::Problem,
        Some(trace_id),
    )
}

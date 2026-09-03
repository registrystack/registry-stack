//! Canonical, bounded client for Base Registry Engine discovery and record reads.
//!
//! Base Registry Engine and Relay share Registry Record semantics, but not routes,
//! queries, Problems, entity tags, or credential eligibility. This client keeps
//! those product contracts explicit while reusing only private transport
//! machinery.

use std::fmt;

use registry_platform_httpsec::{response_trace_id, ProblemDocument, TraceId};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MATCH, LINK, LOCATION, VARY,
};
use reqwest::{Method, Response, StatusCode};
use uuid::Uuid;

use crate::query::{breg_encoded_query, MAX_BREG_REQUEST_URI_BYTES};
use crate::transport::{exact_media_type, Transport};
use crate::*;

const APPLICATION_JSON: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: usize = 4 * 1024;
const MAXIMUM_LOCATION_BYTES: usize = 2_048;

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
        options.append_query(&mut pairs);
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
        decode_breg_single(wire, format)
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
        )
        .await
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
        decode_breg_single(wire, format)
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
        let complete = decode_breg_single(wire, format)?;
        validate_mutation_record(
            &complete,
            StatusCode::CREATED,
            operation.registry_identifier(),
            operation.dataset_identifier(),
            operation.entity_identifier(),
        )?;
        let expected_location = format!(
            "{}/{}",
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
        let complete = decode_breg_single(wire, format)?;
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

    fn validate_create_binding(
        &self,
        operation: &BRegCreateBinding,
        request: &BRegCreateRequest,
    ) -> Result<(), BaseRegistryClientError> {
        if !operation.matches_source(&self.source_binding()) {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine Create operation belongs to another client source",
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

    fn source_binding(&self) -> String {
        self.transport.base_url.as_url().as_str().to_owned()
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
        let complete = decode_breg_collection(wire, format)?;
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
        let body = self
            .transport
            .read(response, self.config.max_response_bytes)
            .await?;
        Ok(BRegWire {
            body,
            metadata: BRegResponseMetadata::new(trace_id, etag),
            media_type: expected_media.to_owned(),
            link,
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

fn decode_breg_single(
    wire: BRegWire,
    format: BRegRecordFormat,
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
    RegistryRecordResponse::from_slice(body, representation).map_err(|_| {
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
    status: u16,
    trace_id: &TraceId,
) -> Result<(), BaseRegistryClientError> {
    if !valid_breg_identifier(entity_identifier) {
        return Err(body_failure(status, trace_id.clone()));
    }
    let expected = format!(
        "<{REGISTRY_RECORD_PROFILE_IDENTIFIER}>; rel=\"profile\", </v1/schemas/{entity_identifier}>; rel=\"describedby\""
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
    let document = match ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES) {
        Ok(value) => value,
        Err(_) => return problem_failure(status, trace_id),
    };
    let code = BRegProblemCode::ALL.into_iter().find(|candidate| {
        document.code == candidate.code()
            && document.status == candidate.status()
            && document.title == candidate.title()
            && document.detail == candidate.detail()
            && document.type_uri == candidate.type_uri()
    });
    let Some(code) = code else {
        return problem_failure(status, trace_id);
    };
    if code.status() != status.as_u16() || document.trace_id != trace_id {
        return problem_failure(status, trace_id);
    }
    BaseRegistryClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id,
    }
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

//! Canonical, bounded client for Registry Server discovery and record reads.
//!
//! Registry Server and Relay share Registry Record semantics, but not routes,
//! queries, Problems, entity tags, or credential eligibility. This client keeps
//! those product contracts explicit while reusing only private transport
//! machinery.

use std::fmt;

use registry_platform_httpsec::{response_trace_id, ProblemDocument, TraceId};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ETAG, LINK};
use reqwest::{Method, Response, StatusCode};
use uuid::Uuid;

use crate::server_query::{server_encoded_query, MAX_SERVER_REQUEST_URI_BYTES};
use crate::transport::{exact_media_type, Transport};
use crate::*;

const APPLICATION_JSON: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: usize = 4 * 1024;

/// One explicitly initiated exchange with one Registry Server deployment.
pub struct RegistryServerClient {
    config: RegistryServerClientConfig,
    transport: Transport,
}

impl RegistryServerClient {
    pub fn new(config: RegistryServerClientConfig) -> Result<Self, RegistryServerClientError> {
        config.validate()?;
        let transport = Transport::new_server(&config)?;
        Ok(Self { config, transport })
    }

    /// Unauthenticated liveness probe. Configured bearer credentials are never
    /// acquired or sent.
    pub async fn health(
        &self,
    ) -> Result<RegistryServerComplete<ProbeStatus>, RegistryServerClientError> {
        self.probe(&["health"], "alive").await
    }

    /// Unauthenticated readiness probe. Configured bearer credentials are
    /// never acquired or sent.
    pub async fn ready(
        &self,
    ) -> Result<RegistryServerComplete<ProbeStatus>, RegistryServerClientError> {
        self.probe(&["ready"], "ready").await
    }

    /// Retrieve the caller-filtered OpenAPI document as inert bounded bytes.
    pub async fn openapi(
        &self,
        access_profile: Option<&str>,
    ) -> Result<RegistryServerComplete<RawDocument>, RegistryServerClientError> {
        self.raw_document(&["openapi.json"], access_profile).await
    }

    /// Retrieve caller-filtered Registry metadata as inert bounded bytes.
    pub async fn registry_metadata(
        &self,
        access_profile: Option<&str>,
    ) -> Result<RegistryServerComplete<RawDocument>, RegistryServerClientError> {
        self.raw_document(&["v1", "registry"], access_profile).await
    }

    /// Retrieve one caller-filtered entity schema as inert bounded bytes.
    pub async fn entity_schema(
        &self,
        entity_identifier: &str,
        access_profile: Option<&str>,
    ) -> Result<RegistryServerComplete<RawDocument>, RegistryServerClientError> {
        validate_server_identifier(
            entity_identifier,
            "the Registry Server entity identifier is invalid",
        )?;
        self.raw_document(&["v1", "schemas", entity_identifier], access_profile)
            .await
    }

    /// Read one canonical UUID record as a Registry Record v1 single envelope.
    pub async fn get_record(
        &self,
        entity_route: &str,
        record_identifier: &str,
        options: &ServerRecordOptions,
    ) -> Result<RegistryServerComplete<RegistryRecordSingleResponse>, RegistryServerClientError>
    {
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
        decode_server_single(wire, format)
    }

    /// Retrieve the first page of one Registry Server record collection.
    pub async fn list_records(
        &self,
        entity_route: &str,
        request: &ServerListRequest,
    ) -> Result<
        RegistryServerComplete<RegistryServerPage<RegistryRecordCollectionResponse>>,
        RegistryServerClientError,
    > {
        validate_entity_route(entity_route)?;
        let pairs = request
            .query_pairs()
            .map_err(|error| RegistryServerClientError::invalid_request(error.reason()))?;
        self.collection_page(
            entity_route,
            &pairs,
            request.record_options().format_value(),
            request.record_options().access_profile_value(),
        )
        .await
    }

    /// Advance exactly one page using an opaque Server continuation.
    pub async fn continue_list(
        &self,
        continuation: &ServerContinuation,
    ) -> Result<
        RegistryServerComplete<RegistryServerPage<RegistryRecordCollectionResponse>>,
        RegistryServerClientError,
    > {
        let pairs = continuation
            .query_pairs()
            .map_err(|error| RegistryServerClientError::invalid_request(error.reason()))?;
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
        request: &ServerLookupRequest,
    ) -> Result<RegistryServerComplete<RegistryRecordSingleResponse>, RegistryServerClientError>
    {
        validate_entity_route(entity_route)?;
        let pairs = request
            .query_pairs()
            .map_err(|error| RegistryServerClientError::invalid_request(error.reason()))?;
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
                    .map_err(|error| RegistryServerClientError::invalid_request(error.reason()))?,
            );
        builder = self.authorize(builder, Credential::Optional).await?;
        let response = self.transport.send_server(builder).await?;
        let wire = self
            .wire(
                response,
                format.media_type(),
                EntityTagExpectation::Forbidden,
            )
            .await?;
        decode_server_single(wire, format)
    }

    async fn probe(
        &self,
        segments: &[&str],
        expected_status: &str,
    ) -> Result<RegistryServerComplete<ProbeStatus>, RegistryServerClientError> {
        let wire = self
            .get(
                segments,
                &[],
                APPLICATION_JSON,
                Credential::None,
                EntityTagExpectation::Forbidden,
            )
            .await?;
        let complete = decode_server_json::<ProbeStatus>(wire)?;
        if complete.value.status != expected_status {
            return Err(RegistryServerClientError::protocol(
                StatusCode::OK.as_u16(),
                RegistryServerProtocolFailure::Body,
                Some(complete.metadata.trace_id().clone()),
            ));
        }
        Ok(complete)
    }

    async fn raw_document(
        &self,
        segments: &[&str],
        access_profile: Option<&str>,
    ) -> Result<RegistryServerComplete<RawDocument>, RegistryServerClientError> {
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
        Ok(RegistryServerComplete {
            value: RawDocument::new(wire.media_type, wire.body),
            metadata: wire.metadata,
        })
    }

    async fn collection_page(
        &self,
        entity_route: &str,
        pairs: &[(String, String)],
        format: ServerRecordFormat,
        access_profile: Option<&str>,
    ) -> Result<
        RegistryServerComplete<RegistryServerPage<RegistryRecordCollectionResponse>>,
        RegistryServerClientError,
    > {
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
        let complete = decode_server_collection(wire, format)?;
        let continuation = complete
            .value
            .page_info
            .next_cursor
            .as_ref()
            .map(|cursor| {
                ServerContinuation::try_from_parts(
                    entity_route,
                    cursor,
                    format,
                    access_profile.map(str::to_owned),
                )
            })
            .transpose()
            .map_err(|_| {
                RegistryServerClientError::protocol(
                    StatusCode::OK.as_u16(),
                    RegistryServerProtocolFailure::Body,
                    Some(complete.metadata.trace_id().clone()),
                )
            })?;
        Ok(RegistryServerComplete {
            value: RegistryServerPage {
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
    ) -> Result<ServerWire, RegistryServerClientError> {
        let url = self.url_with_query(segments, pairs)?;
        let mut builder = self.transport.http.get(url).header(ACCEPT, accept);
        builder = self.authorize(builder, credential).await?;
        let response = self.transport.send_server(builder).await?;
        self.wire(response, accept, etag).await
    }

    async fn authorize(
        &self,
        mut builder: reqwest::RequestBuilder,
        credential: Credential,
    ) -> Result<reqwest::RequestBuilder, RegistryServerClientError> {
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
    ) -> Result<reqwest::Url, RegistryServerClientError> {
        let mut url = self.transport.server_url(segments)?;
        if !pairs.is_empty() {
            url.set_query(Some(&server_encoded_query(pairs)));
        }
        if url.as_str().len() > MAX_SERVER_REQUEST_URI_BYTES {
            return Err(RegistryServerClientError::invalid_request(
                "the Registry Server request URI exceeds the client bound",
            ));
        }
        Ok(url)
    }

    async fn wire(
        &self,
        response: Response,
        expected_media: &str,
        etag_expectation: EntityTagExpectation,
    ) -> Result<ServerWire, RegistryServerClientError> {
        let status = response.status();
        if status != StatusCode::OK {
            return Err(server_problem(response, &self.transport).await);
        }
        let headers = response.headers().clone();
        let trace_id = server_trace_id(status, &headers)?;
        if !exact_media_type(&headers, expected_media) {
            return Err(RegistryServerClientError::protocol(
                status.as_u16(),
                RegistryServerProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let etag = server_response_etag(status, &headers, &trace_id)?;
        if matches!(etag_expectation, EntityTagExpectation::Required) != etag.is_some() {
            return Err(RegistryServerClientError::protocol(
                status.as_u16(),
                RegistryServerProtocolFailure::EntityTag,
                Some(trace_id),
            ));
        }
        let link = server_response_link(status, &headers, &trace_id)?;
        let body = self
            .transport
            .read_server(response, self.config.max_response_bytes)
            .await?;
        Ok(ServerWire {
            body,
            metadata: RegistryServerResponseMetadata::new(trace_id, etag),
            media_type: expected_media.to_owned(),
            link,
        })
    }
}

impl fmt::Debug for RegistryServerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerClient")
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

struct ServerWire {
    body: Vec<u8>,
    metadata: RegistryServerResponseMetadata,
    media_type: String,
    link: Option<String>,
}

fn decode_server_json<T: serde::de::DeserializeOwned>(
    wire: ServerWire,
) -> Result<RegistryServerComplete<T>, RegistryServerClientError> {
    let value = serde_json::from_slice(&wire.body).map_err(|_| {
        RegistryServerClientError::protocol(
            StatusCode::OK.as_u16(),
            RegistryServerProtocolFailure::Body,
            Some(wire.metadata.trace_id().clone()),
        )
    })?;
    Ok(RegistryServerComplete {
        value,
        metadata: wire.metadata,
    })
}

fn decode_server_single(
    wire: ServerWire,
    format: ServerRecordFormat,
) -> Result<RegistryServerComplete<RegistryRecordSingleResponse>, RegistryServerClientError> {
    let trace_id = wire.metadata.trace_id().clone();
    let link = wire.link.clone();
    let value = decode_registry_record(&wire.body, format, &trace_id)?;
    let RegistryRecordResponse::Single(value) = value else {
        return Err(body_failure(trace_id));
    };
    validate_server_records(std::slice::from_ref(&value.data), &trace_id)?;
    validate_profile_link(
        link.as_deref(),
        &value.meta.entity_type_identifier,
        &trace_id,
    )?;
    Ok(RegistryServerComplete {
        value,
        metadata: wire.metadata,
    })
}

fn decode_server_collection(
    wire: ServerWire,
    format: ServerRecordFormat,
) -> Result<RegistryServerComplete<RegistryRecordCollectionResponse>, RegistryServerClientError> {
    let trace_id = wire.metadata.trace_id().clone();
    let link = wire.link.clone();
    let value = decode_registry_record(&wire.body, format, &trace_id)?;
    let RegistryRecordResponse::Collection(value) = value else {
        return Err(body_failure(trace_id));
    };
    validate_server_records(&value.items, &trace_id)?;
    validate_profile_link(
        link.as_deref(),
        &value.meta.entity_type_identifier,
        &trace_id,
    )?;
    Ok(RegistryServerComplete {
        value,
        metadata: wire.metadata,
    })
}

fn decode_registry_record(
    body: &[u8],
    format: ServerRecordFormat,
    trace_id: &TraceId,
) -> Result<RegistryRecordResponse, RegistryServerClientError> {
    let representation = match format {
        ServerRecordFormat::Json => RegistryRecordRepresentation::Json,
        ServerRecordFormat::JsonLd => RegistryRecordRepresentation::JsonLdSharedContext,
    };
    RegistryRecordResponse::from_slice(body, representation).map_err(|_| {
        RegistryServerClientError::protocol(
            StatusCode::OK.as_u16(),
            RegistryServerProtocolFailure::Body,
            Some(trace_id.clone()),
        )
    })
}

fn validate_server_records(
    records: &[RegistryRecord],
    trace_id: &TraceId,
) -> Result<(), RegistryServerClientError> {
    if records.iter().any(|record| {
        !canonical_uuid(&record.record_identifier)
            || !canonical_positive_revision(&record.revision_identifier)
    }) {
        return Err(body_failure(trace_id.clone()));
    }
    Ok(())
}

fn validate_profile_link(
    actual: Option<&str>,
    entity_identifier: &str,
    trace_id: &TraceId,
) -> Result<(), RegistryServerClientError> {
    if !valid_server_identifier(entity_identifier) {
        return Err(body_failure(trace_id.clone()));
    }
    let expected = format!(
        "<{REGISTRY_RECORD_PROFILE_IDENTIFIER}>; rel=\"profile\", </v1/schemas/{entity_identifier}>; rel=\"describedby\""
    );
    if actual != Some(expected.as_str()) {
        return Err(RegistryServerClientError::protocol(
            StatusCode::OK.as_u16(),
            RegistryServerProtocolFailure::ProfileLink,
            Some(trace_id.clone()),
        ));
    }
    Ok(())
}

fn access_profile_query(
    access_profile: Option<&str>,
) -> Result<Vec<(String, String)>, RegistryServerClientError> {
    let Some(access_profile) = access_profile else {
        return Ok(Vec::new());
    };
    let options = ServerRecordOptions::default()
        .access_profile(access_profile)
        .map_err(|error| RegistryServerClientError::invalid_request(error.reason()))?;
    let mut pairs = Vec::with_capacity(1);
    options.append_query(&mut pairs);
    Ok(pairs)
}

fn validate_entity_route(value: &str) -> Result<(), RegistryServerClientError> {
    validate_server_identifier(value, "the Registry Server entity route is invalid")
}

fn validate_server_identifier(
    value: &str,
    reason: &'static str,
) -> Result<(), RegistryServerClientError> {
    if !valid_server_identifier(value) {
        return Err(RegistryServerClientError::invalid_request(reason));
    }
    Ok(())
}

fn valid_server_identifier(value: &str) -> bool {
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

fn validate_record_uuid(value: &str) -> Result<(), RegistryServerClientError> {
    if !canonical_uuid(value) {
        return Err(RegistryServerClientError::invalid_request(
            "the Registry Server record identifier must be a canonical lowercase UUID",
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

fn server_trace_id(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<TraceId, RegistryServerClientError> {
    response_trace_id(headers).map_err(|_| {
        RegistryServerClientError::protocol(
            status.as_u16(),
            RegistryServerProtocolFailure::TraceContext,
            None,
        )
    })
}

fn server_response_etag(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    trace_id: &TraceId,
) -> Result<Option<RegistryServerEtag>, RegistryServerClientError> {
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
    RegistryServerEtag::parse(value)
        .map(Some)
        .map_err(|_| etag_failure(status, trace_id.clone()))
}

fn server_response_link(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    trace_id: &TraceId,
) -> Result<Option<String>, RegistryServerClientError> {
    let mut values = headers.get_all(LINK).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RegistryServerClientError::protocol(
            status.as_u16(),
            RegistryServerProtocolFailure::ProfileLink,
            Some(trace_id.clone()),
        ));
    }
    value.to_str().map(str::to_owned).map(Some).map_err(|_| {
        RegistryServerClientError::protocol(
            status.as_u16(),
            RegistryServerProtocolFailure::ProfileLink,
            Some(trace_id.clone()),
        )
    })
}

async fn server_problem(response: Response, transport: &Transport) -> RegistryServerClientError {
    let status = response.status();
    let headers = response.headers().clone();
    let trace_id = match server_trace_id(status, &headers) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if !exact_media_type(&headers, PROBLEM_MEDIA_TYPE) {
        return RegistryServerClientError::protocol(
            status.as_u16(),
            RegistryServerProtocolFailure::MediaType,
            Some(trace_id),
        );
    }
    let body = match transport
        .read_server(response, MAXIMUM_PROBLEM_BYTES as u64)
        .await
    {
        Ok(value) => value,
        Err(error) => return error,
    };
    let document = match ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES) {
        Ok(value) => value,
        Err(_) => return problem_failure(status, trace_id),
    };
    let code = RegistryServerProblemCode::ALL
        .into_iter()
        .find(|candidate| {
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
    RegistryServerClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id,
    }
}

fn body_failure(trace_id: TraceId) -> RegistryServerClientError {
    RegistryServerClientError::protocol(
        StatusCode::OK.as_u16(),
        RegistryServerProtocolFailure::Body,
        Some(trace_id),
    )
}

fn etag_failure(status: StatusCode, trace_id: TraceId) -> RegistryServerClientError {
    RegistryServerClientError::protocol(
        status.as_u16(),
        RegistryServerProtocolFailure::EntityTag,
        Some(trace_id),
    )
}

fn problem_failure(status: StatusCode, trace_id: TraceId) -> RegistryServerClientError {
    RegistryServerClientError::protocol(
        status.as_u16(),
        RegistryServerProtocolFailure::Problem,
        Some(trace_id),
    )
}

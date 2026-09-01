use std::fmt;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, IF_NONE_MATCH};
use reqwest::{Method, Response, StatusCode};
use serde::de::DeserializeOwned;

use crate::query::encoded_query;
use crate::response::CollectionRoute;
use crate::transport::{exact_media_type, problem, response_etag, trace_id, Transport};
use crate::*;

const APPLICATION_JSON: &str = "application/json";
const APPLICATION_GEO_JSON: &str = "application/geo+json";
const SDMX_STRUCTURE_JSON: &str = "application/vnd.sdmx.structure+json;version=2.1.0";

/// One explicitly initiated exchange with one Relay deployment.
pub struct RelayClient {
    config: RelayClientConfig,
    transport: Transport,
}

impl RelayClient {
    pub fn new(config: RelayClientConfig) -> Result<Self, RelayClientError> {
        config.validate()?;
        let transport = Transport::new(&config)?;
        Ok(Self { config, transport })
    }

    /// Unauthenticated liveness probe.
    pub async fn health(&self) -> Result<Complete<ProbeStatus>, RelayClientError> {
        self.probe(&["health"]).await
    }

    /// Unauthenticated readiness probe.
    pub async fn ready(&self) -> Result<Complete<ProbeStatus>, RelayClientError> {
        self.probe(&["ready"]).await
    }

    /// Unauthenticated public OpenAPI artifact.
    pub async fn openapi(
        &self,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<RawDocument>, RelayClientError> {
        let wire = self
            .get(
                &["openapi.json"],
                &[],
                APPLICATION_JSON,
                etag,
                Credential::None,
            )
            .await?;
        decode_raw_conditional(wire)
    }

    pub async fn service_metadata(
        &self,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<ServiceMetadata>, RelayClientError> {
        let wire = self
            .get(&["v2"], &[], APPLICATION_JSON, etag, Credential::Optional)
            .await?;
        decode_json_conditional(wire, APPLICATION_JSON)
    }

    pub async fn resources(
        &self,
        request: ResourceListRequest,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<ResourcePage<ResourceCollection>>, RelayClientError> {
        self.resource_page(request.pairs(), etag).await
    }

    pub async fn continue_resources(
        &self,
        continuation: &ResourceContinuation,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<ResourcePage<ResourceCollection>>, RelayClientError> {
        self.resource_page(vec![("cursor".into(), continuation.cursor.clone())], etag)
            .await
    }

    pub async fn resource(
        &self,
        resource: &str,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<ResourceEnvelope>, RelayClientError> {
        validate_route_identifier(resource)?;
        let wire = self
            .get(
                &["v2", "resources", resource],
                &[],
                APPLICATION_JSON,
                etag,
                Credential::Optional,
            )
            .await?;
        decode_json_conditional(wire, APPLICATION_JSON)
    }

    pub async fn list_records(
        &self,
        resource: &str,
        request: &ListRequest,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<CollectionPage<RecordCollectionResponse>>, RelayClientError> {
        validate_route_identifier(resource)?;
        let route = CollectionRoute::Records {
            resource: resource.to_owned(),
        };
        self.collection_page(route, request.pairs()?, request.record_options(), etag)
            .await
    }

    pub async fn search_records(
        &self,
        resource: &str,
        search: &str,
        request: &SearchRequest,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<CollectionPage<RecordCollectionResponse>>, RelayClientError> {
        validate_route_identifier(resource)?;
        validate_route_identifier(search)?;
        let route = CollectionRoute::Search {
            resource: resource.to_owned(),
            search: search.to_owned(),
        };
        self.collection_page(route, request.pairs()?, request.record_options(), etag)
            .await
    }

    /// Advance exactly one page when the caller explicitly supplies a continuation.
    pub async fn continue_collection(
        &self,
        continuation: &CollectionContinuation,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<CollectionPage<RecordCollectionResponse>>, RelayClientError> {
        let mut pairs = vec![("cursor".into(), continuation.cursor.clone())];
        if let Some(access_profile) = &continuation.access_profile {
            pairs.push(("accessProfile".into(), access_profile.clone()));
        }
        let options = RecordOptions {
            fields: Vec::new(),
            access_profile: continuation.access_profile.clone(),
            format: continuation.format,
        };
        self.collection_page(continuation.route.clone(), pairs, options, etag)
            .await
    }

    pub async fn read_record(
        &self,
        resource: &str,
        record_identifier: &str,
        options: &RecordOptions,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<RecordResponse>, RelayClientError> {
        validate_route_identifier(resource)?;
        validate_record_identifier(record_identifier)?;
        let mut pairs = Vec::new();
        options.append_query(&mut pairs);
        let wire = self
            .get(
                &["v2", "resources", resource, "records", record_identifier],
                &pairs,
                options.format.media_type(),
                etag,
                Credential::Optional,
            )
            .await?;
        decode_record_conditional(wire, options.format)
    }

    pub async fn lookup_record(
        &self,
        resource: &str,
        lookup: &str,
        request: &LookupRequest,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<RecordResponse>, RelayClientError> {
        validate_route_identifier(resource)?;
        validate_route_identifier(lookup)?;
        let mut pairs = Vec::new();
        request.options.append_query(&mut pairs);
        let url = self.url_with_query(&["v2", "resources", resource, "lookups", lookup], &pairs)?;
        let mut builder = self
            .transport
            .http
            .request(Method::POST, url)
            .header(ACCEPT, request.options.format.media_type())
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(request.body()?);
        builder = self.authorize(builder, Credential::Optional).await?;
        if let Some(etag) = etag {
            builder = builder.header(IF_NONE_MATCH, etag.as_str());
        }
        let response = self.transport.send(builder).await?;
        let wire = self
            .wire(response, Some(request.options.format.media_type()), etag)
            .await?;
        decode_record_conditional(wire, request.options.format)
    }

    /// Retrieve an artifact and preserve its single bounded server media type.
    pub async fn artifact(
        &self,
        artifact_identifier: &str,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<RawDocument>, RelayClientError> {
        validate_artifact_identifier(artifact_identifier)?;
        let url = self.url_with_query(&["v2", "artifacts", artifact_identifier], &[])?;
        let mut builder = self.transport.http.get(url).header(ACCEPT, "*/*");
        builder = self.authorize(builder, Credential::Optional).await?;
        if let Some(etag) = etag {
            builder = builder.header(IF_NONE_MATCH, etag.as_str());
        }
        let response = self.transport.send(builder).await?;
        let wire = self.wire(response, None, etag).await?;
        decode_raw_conditional(wire)
    }

    pub async fn sdmx_data(
        &self,
        request: &SdmxDataRequest,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<RawDocument>, RelayClientError> {
        let pairs = request.pairs()?;
        let mut segments = vec![
            "sdmx",
            "v2",
            "data",
            "dataflow",
            request.agency.as_str(),
            request.resource.as_str(),
            request.version.as_str(),
        ];
        if let Some(key) = &request.key {
            segments.push(key);
        }
        let wire = self
            .get(
                &segments,
                &pairs,
                request.format.media_type(),
                etag,
                Credential::Optional,
            )
            .await?;
        decode_raw_conditional(wire)
    }

    pub async fn sdmx_structure(
        &self,
        request: &SdmxStructureRequest,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<RawDocument>, RelayClientError> {
        let wire = self
            .get(
                &[
                    "sdmx",
                    "v2",
                    "structure",
                    request.kind().path(),
                    request.agency(),
                    request.resource(),
                    request.version(),
                ],
                &[("references".into(), "none".into())],
                SDMX_STRUCTURE_JSON,
                etag,
                Credential::Optional,
            )
            .await?;
        decode_raw_conditional(wire)
    }

    async fn probe(&self, segments: &[&str]) -> Result<Complete<ProbeStatus>, RelayClientError> {
        let wire = self
            .get(segments, &[], APPLICATION_JSON, None, Credential::None)
            .await?;
        match decode_json_conditional::<ProbeStatus>(wire, APPLICATION_JSON)? {
            Conditional::Complete(value) => Ok(value),
            Conditional::NotModified(_) => Err(RelayClientError::protocol(
                304,
                ProtocolFailure::Status,
                None,
            )),
        }
    }

    async fn resource_page(
        &self,
        pairs: Vec<(String, String)>,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<ResourcePage<ResourceCollection>>, RelayClientError> {
        let wire = self
            .get(
                &["v2", "resources"],
                &pairs,
                APPLICATION_JSON,
                etag,
                Credential::Optional,
            )
            .await?;
        match decode_json_conditional::<ResourceCollection>(wire, APPLICATION_JSON)? {
            Conditional::NotModified(value) => Ok(Conditional::NotModified(value)),
            Conditional::Complete(Complete { value, metadata }) => {
                let continuation = value
                    .page_info
                    .next_cursor
                    .as_ref()
                    .map(|cursor| ResourceContinuation::try_from_cursor(cursor.clone()))
                    .transpose()
                    .map_err(|_| {
                        RelayClientError::protocol(
                            200,
                            ProtocolFailure::Body,
                            Some(metadata.trace_id().clone()),
                        )
                    })?;
                Ok(Conditional::Complete(Complete {
                    value: ResourcePage {
                        value,
                        continuation,
                    },
                    metadata,
                }))
            }
        }
    }

    async fn collection_page(
        &self,
        route: CollectionRoute,
        pairs: Vec<(String, String)>,
        options: RecordOptions,
        etag: Option<&StrongEtag>,
    ) -> Result<Conditional<CollectionPage<RecordCollectionResponse>>, RelayClientError> {
        let segments = match &route {
            CollectionRoute::Records { resource } => {
                vec!["v2", "resources", resource.as_str(), "records"]
            }
            CollectionRoute::Search { resource, search } => vec![
                "v2",
                "resources",
                resource.as_str(),
                "searches",
                search.as_str(),
            ],
        };
        let wire = self
            .get(
                &segments,
                &pairs,
                options.format.media_type(),
                etag,
                Credential::Optional,
            )
            .await?;
        match decode_collection_conditional(wire, options.format)? {
            Conditional::NotModified(value) => Ok(Conditional::NotModified(value)),
            Conditional::Complete(Complete { value, metadata }) => {
                let cursor = match &value {
                    RecordCollectionResponse::Json(value) => value.page_info.next_cursor.as_ref(),
                    RecordCollectionResponse::GeoJson(value) => {
                        value.page_info.next_cursor.as_ref()
                    }
                };
                let continuation = cursor
                    .map(|cursor| {
                        let route = match &route {
                            CollectionRoute::Records { resource } => {
                                CollectionRouteProjection::Records {
                                    resource: resource.clone(),
                                }
                            }
                            CollectionRoute::Search { resource, search } => {
                                CollectionRouteProjection::Search {
                                    resource: resource.clone(),
                                    search: search.clone(),
                                }
                            }
                        };
                        CollectionContinuation::try_from_projection(
                            CollectionContinuationProjection {
                                route,
                                cursor: cursor.clone(),
                                format: options.format,
                                access_profile: options.access_profile.clone(),
                            },
                        )
                    })
                    .transpose()
                    .map_err(|_| {
                        RelayClientError::protocol(
                            200,
                            ProtocolFailure::Body,
                            Some(metadata.trace_id().clone()),
                        )
                    })?;
                Ok(Conditional::Complete(Complete {
                    value: CollectionPage {
                        value,
                        continuation,
                    },
                    metadata,
                }))
            }
        }
    }

    async fn get(
        &self,
        segments: &[&str],
        pairs: &[(String, String)],
        accept: &str,
        etag: Option<&StrongEtag>,
        credential: Credential,
    ) -> Result<WireOutcome, RelayClientError> {
        let url = self.url_with_query(segments, pairs)?;
        let mut builder = self.transport.http.get(url).header(ACCEPT, accept);
        builder = self.authorize(builder, credential).await?;
        if let Some(etag) = etag {
            builder = builder.header(IF_NONE_MATCH, etag.as_str());
        }
        let response = self.transport.send(builder).await?;
        self.wire(response, Some(accept), etag).await
    }

    async fn authorize(
        &self,
        mut builder: reqwest::RequestBuilder,
        credential: Credential,
    ) -> Result<reqwest::RequestBuilder, RelayClientError> {
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
    ) -> Result<reqwest::Url, RelayClientError> {
        let mut url = self.transport.url(segments)?;
        if !pairs.is_empty() {
            url.set_query(Some(&encoded_query(pairs)));
        }
        if url.as_str().len() > 16 * 1024 {
            return Err(RelayClientError::invalid_request(
                "the request URI exceeds the client bound",
            ));
        }
        Ok(url)
    }

    async fn wire(
        &self,
        response: Response,
        expected_media: Option<&str>,
        conditional: Option<&StrongEtag>,
    ) -> Result<WireOutcome, RelayClientError> {
        let status = response.status();
        if status != StatusCode::OK && status != StatusCode::NOT_MODIFIED {
            return Err(problem(response, &self.transport).await);
        }
        let headers = response.headers().clone();
        let trace = trace_id(status, &headers)?;
        let etag = response_etag(status, &headers)?;
        if status == StatusCode::NOT_MODIFIED {
            let Some(expected) = conditional else {
                return Err(RelayClientError::protocol(
                    status.as_u16(),
                    ProtocolFailure::Status,
                    Some(trace),
                ));
            };
            let Some(actual) = etag else {
                return Err(RelayClientError::protocol(
                    status.as_u16(),
                    ProtocolFailure::EntityTag,
                    Some(trace),
                ));
            };
            if &actual != expected {
                return Err(RelayClientError::protocol(
                    status.as_u16(),
                    ProtocolFailure::EntityTag,
                    Some(trace),
                ));
            }
            let body_is_empty = self.transport.not_modified_body_is_empty(response).await?;
            return not_modified_outcome(actual, trace, body_is_empty);
        }
        let media_type = match expected_media {
            Some(expected) if exact_media_type(&headers, expected) => expected.to_owned(),
            Some(_) => {
                return Err(RelayClientError::protocol(
                    status.as_u16(),
                    ProtocolFailure::MediaType,
                    Some(trace),
                ))
            }
            None => response_media_type(&headers).map_err(|_| {
                RelayClientError::protocol(
                    status.as_u16(),
                    ProtocolFailure::MediaType,
                    Some(trace.clone()),
                )
            })?,
        };
        let body = self
            .transport
            .read(response, self.config.max_response_bytes)
            .await?;
        Ok(WireOutcome::Complete {
            body,
            metadata: ResponseMetadata::new(trace, etag),
            media_type,
        })
    }
}

fn not_modified_outcome(
    etag: StrongEtag,
    trace_id: registry_platform_httpsec::TraceId,
    body_is_empty: bool,
) -> Result<WireOutcome, RelayClientError> {
    if !body_is_empty {
        return Err(RelayClientError::protocol(
            StatusCode::NOT_MODIFIED.as_u16(),
            ProtocolFailure::NotModifiedBody,
            Some(trace_id),
        ));
    }
    Ok(WireOutcome::NotModified(NotModified { etag, trace_id }))
}

impl fmt::Debug for RelayClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum Credential {
    None,
    Optional,
}

enum WireOutcome {
    Complete {
        body: Vec<u8>,
        metadata: ResponseMetadata,
        media_type: String,
    },
    NotModified(NotModified),
}

fn decode_json_conditional<T: DeserializeOwned>(
    wire: WireOutcome,
    _media: &str,
) -> Result<Conditional<T>, RelayClientError> {
    match wire {
        WireOutcome::NotModified(value) => Ok(Conditional::NotModified(value)),
        WireOutcome::Complete { body, metadata, .. } => {
            let value = serde_json::from_slice(&body).map_err(|_| {
                RelayClientError::protocol(
                    200,
                    ProtocolFailure::Body,
                    Some(metadata.trace_id().clone()),
                )
            })?;
            Ok(Conditional::Complete(Complete { value, metadata }))
        }
    }
}

fn decode_raw_conditional(wire: WireOutcome) -> Result<Conditional<RawDocument>, RelayClientError> {
    Ok(match wire {
        WireOutcome::NotModified(value) => Conditional::NotModified(value),
        WireOutcome::Complete {
            body,
            metadata,
            media_type,
        } => Conditional::Complete(Complete {
            value: RawDocument::new(media_type, body),
            metadata,
        }),
    })
}

fn decode_record_conditional(
    wire: WireOutcome,
    format: RecordFormat,
) -> Result<Conditional<RecordResponse>, RelayClientError> {
    match format {
        RecordFormat::Json => {
            decode_registry_record_conditional(wire, RecordEnvelope::matches_json_representation)
                .map(|value| map_conditional(value, RecordResponse::Json))
        }
        RecordFormat::JsonLd => {
            decode_registry_record_conditional(wire, RecordEnvelope::matches_json_ld_representation)
                .map(|value| map_conditional(value, RecordResponse::Json))
        }
        RecordFormat::GeoJsonRfc7946 | RecordFormat::JsonFg => {
            decode_json_conditional::<GeoJsonFeature>(wire, APPLICATION_GEO_JSON)
                .map(|value| map_conditional(value, RecordResponse::GeoJson))
        }
    }
}

fn decode_collection_conditional(
    wire: WireOutcome,
    format: RecordFormat,
) -> Result<Conditional<RecordCollectionResponse>, RelayClientError> {
    match format {
        RecordFormat::Json => decode_registry_record_collection_conditional(
            wire,
            RecordCollection::matches_json_representation,
        )
        .map(|value| map_conditional(value, RecordCollectionResponse::Json)),
        RecordFormat::JsonLd => decode_registry_record_collection_conditional(
            wire,
            RecordCollection::matches_json_ld_representation,
        )
        .map(|value| map_conditional(value, RecordCollectionResponse::Json)),
        RecordFormat::GeoJsonRfc7946 | RecordFormat::JsonFg => {
            decode_json_conditional::<GeoJsonFeatureCollection>(wire, APPLICATION_GEO_JSON)
                .map(|value| map_conditional(value, RecordCollectionResponse::GeoJson))
        }
    }
}

fn decode_registry_record_conditional(
    wire: WireOutcome,
    validates_representation: impl FnOnce(&RecordEnvelope) -> bool,
) -> Result<Conditional<RecordEnvelope>, RelayClientError> {
    validate_record_representation(
        decode_json_conditional::<RecordEnvelope>(wire, APPLICATION_JSON)?,
        validates_representation,
    )
}

fn decode_registry_record_collection_conditional(
    wire: WireOutcome,
    validates_representation: impl FnOnce(&RecordCollection) -> bool,
) -> Result<Conditional<RecordCollection>, RelayClientError> {
    validate_record_representation(
        decode_json_conditional::<RecordCollection>(wire, APPLICATION_JSON)?,
        validates_representation,
    )
}

fn validate_record_representation<T>(
    value: Conditional<T>,
    validates_representation: impl FnOnce(&T) -> bool,
) -> Result<Conditional<T>, RelayClientError> {
    match value {
        Conditional::Complete(complete) if !validates_representation(&complete.value) => {
            Err(RelayClientError::protocol(
                200,
                ProtocolFailure::Body,
                Some(complete.metadata.trace_id().clone()),
            ))
        }
        value => Ok(value),
    }
}

fn map_conditional<T, U>(value: Conditional<T>, map: impl FnOnce(T) -> U) -> Conditional<U> {
    match value {
        Conditional::Complete(Complete { value, metadata }) => Conditional::Complete(Complete {
            value: map(value),
            metadata,
        }),
        Conditional::NotModified(value) => Conditional::NotModified(value),
    }
}

fn validate_route_identifier(value: &str) -> Result<(), RelayClientError> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(RelayClientError::invalid_request(
            "a route identifier is invalid",
        ));
    }
    Ok(())
}

fn validate_record_identifier(value: &str) -> Result<(), RelayClientError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(RelayClientError::invalid_request(
            "the record identifier is invalid",
        ));
    }
    Ok(())
}

fn validate_artifact_identifier(value: &str) -> Result<(), RelayClientError> {
    if value.is_empty()
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        return Err(RelayClientError::invalid_request(
            "the artifact identifier is invalid",
        ));
    }
    Ok(())
}

fn response_media_type(headers: &reqwest::header::HeaderMap) -> Result<String, ()> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().map_err(|_| ())?,
        _ => return Err(()),
    };
    let mut parts = value.split(';');
    let essence = parts.next().ok_or(())?.trim();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return Err(());
    };
    if subtype.contains('/') || !media_token(kind) || !media_token(subtype) {
        return Err(());
    }
    for parameter in parts {
        let Some((name, parameter_value)) = parameter.trim().split_once('=') else {
            return Err(());
        };
        if !media_token(name)
            || !(media_token(parameter_value) || quoted_media_parameter(parameter_value))
        {
            return Err(());
        }
    }
    Ok(value.to_owned())
}

fn media_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn quoted_media_parameter(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return false;
    }
    let mut escaped = false;
    for byte in &bytes[1..bytes.len() - 1] {
        if escaped {
            if byte.is_ascii_control() {
                return false;
            }
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' || byte.is_ascii_control() {
            return false;
        }
    }
    !escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Response as HttpResponse;
    use url::Url;

    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const ETAG: &str = "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";

    fn not_modified_response(etag: Option<&str>, body: &[u8]) -> Response {
        let mut builder = HttpResponse::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("traceparent", TRACEPARENT)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .header("content-length", "4096");
        if let Some(etag) = etag {
            builder = builder.header("etag", etag);
        }
        builder
            .body(reqwest::Body::from(body.to_vec()))
            .expect("test response")
            .into()
    }

    #[tokio::test]
    async fn not_modified_requires_matching_strong_sha256_etag_and_empty_body() {
        let client = RelayClient::new(RelayClientConfig::new(
            Url::parse("http://127.0.0.1:1/prefix").expect("base URL"),
        ))
        .expect("client");
        let expected = StrongEtag::parse(ETAG).expect("etag");

        let response = not_modified_response(Some(ETAG), b"");
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .expect("content length"),
            "4096"
        );
        assert!(matches!(
            client
                .wire(response, Some(APPLICATION_JSON), Some(&expected))
                .await,
            Ok(WireOutcome::NotModified(_))
        ));

        for response in [
            not_modified_response(None, b""),
            not_modified_response(
                Some("\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""),
                b"",
            ),
        ] {
            assert!(matches!(
                client
                    .wire(response, Some(APPLICATION_JSON), Some(&expected))
                    .await,
                Err(RelayClientError::Protocol { .. })
            ));
        }

        let trace = registry_platform_httpsec::TraceId::parse("4bf92f3577b34da6a3ce929d0e0e4736")
            .expect("trace ID");
        assert!(matches!(
            not_modified_outcome(expected, trace, false),
            Err(RelayClientError::Protocol { .. })
        ));
    }
}

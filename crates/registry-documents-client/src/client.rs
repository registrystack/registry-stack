// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::time::Duration;

use registry_documents_core::{
    type_uri, DocumentGrantPage, DocumentGrantView, DocumentPage, DocumentPolicyList, DocumentView,
    IssueGrantRequest, ProblemCode, ReservationView, ReserveDocumentRequest, DOCUMENTS_PATH,
    DOCUMENT_CONTENT_PATH, DOCUMENT_ERASURE_PATH, DOCUMENT_GRANTS_PATH, DOCUMENT_PATH, GRANTS_PATH,
    GRANT_PATH, HEALTH_PATH, IDEMPOTENCY_KEY_HEADER, MAXIMUM_IDEMPOTENCY_KEY_BYTES,
    MAXIMUM_PAGE_SIZE, POLICIES_PATH, UPLOAD_CONTENT_PATH,
};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, BearerToken, OutboundOptions,
    ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers, BoundedReadError,
};
use registry_platform_yaml::Digest;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{DocumentsClientError, DocumentsProtocolFailure};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;
const DEFAULT_MAXIMUM_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_MAXIMUM_DOWNLOAD_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// The body of a content upload: in memory, or streamed from any
/// `http_body::Body` through `UploadBody::wrap`. A streamed body is sent as
/// it is produced and never buffered by the client.
pub type UploadBody = reqwest::Body;

/// Where the Document Store lives and the bounds every exchange with it is
/// held to. Nothing here is checked until `DocumentsClient::new`, which
/// refuses an unusable configuration before any client exists.
#[derive(Clone)]
pub struct DocumentsClientConfig {
    base_url: Url,
    attempt_timeout: Duration,
    connect_timeout: Duration,
    user_agent: Option<String>,
    trusted_root_certificates: Option<Vec<u8>>,
    maximum_response_bytes: u64,
    maximum_download_bytes: u64,
}

impl DocumentsClientConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            attempt_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
            maximum_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
            maximum_download_bytes: DEFAULT_MAXIMUM_DOWNLOAD_BYTES,
        }
    }

    #[must_use]
    pub fn with_attempt_timeout(mut self, value: Duration) -> Self {
        self.attempt_timeout = value;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, value: Duration) -> Self {
        self.connect_timeout = value;
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, value: impl Into<String>) -> Self {
        self.user_agent = Some(value.into());
        self
    }

    #[must_use]
    pub fn with_trusted_root_certificates(mut self, value: Vec<u8>) -> Self {
        self.trusted_root_certificates = Some(value);
        self
    }

    /// The most bytes a JSON answer may carry: 4 MiB by default, at most
    /// 16 MiB.
    #[must_use]
    pub fn with_maximum_response_bytes(mut self, value: u64) -> Self {
        self.maximum_response_bytes = value;
        self
    }

    /// The most bytes released content may carry: 16 MiB by default, at most
    /// 64 MiB. A download is held in memory until its digest is checked, so
    /// this bound is also the most memory one download may take.
    #[must_use]
    pub fn with_maximum_download_bytes(mut self, value: u64) -> Self {
        self.maximum_download_bytes = value;
        self
    }

    fn validate(&self) -> Result<ServiceBaseUrl, DocumentsClientError> {
        let base_url = ServiceBaseUrl::new(self.base_url.clone()).map_err(|_| {
            DocumentsClientError::configuration("the service base URL is not usable")
        })?;
        if self.attempt_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(DocumentsClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self.maximum_response_bytes == 0 || self.maximum_response_bytes > MAXIMUM_RESPONSE_BYTES
        {
            return Err(DocumentsClientError::configuration(
                "the response byte bound must be between 1 byte and 16 MiB",
            ));
        }
        if self.maximum_download_bytes == 0 || self.maximum_download_bytes > MAXIMUM_DOWNLOAD_BYTES
        {
            return Err(DocumentsClientError::configuration(
                "the download byte bound must be between 1 byte and 64 MiB",
            ));
        }
        if self
            .trusted_root_certificates
            .as_ref()
            .is_some_and(|value| value.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
        {
            return Err(DocumentsClientError::configuration(
                "the trusted root certificate bundle exceeds the accepted bound",
            ));
        }
        Ok(base_url)
    }
}

impl fmt::Debug for DocumentsClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentsClientConfig")
            .field("base_url", &"<validated service URL>")
            .field("attempt_timeout", &self.attempt_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("user_agent_present", &self.user_agent.is_some())
            .field(
                "trusted_root_certificates_present",
                &self.trusted_root_certificates.is_some(),
            )
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("maximum_download_bytes", &self.maximum_download_bytes)
            .finish()
    }
}

/// One completed call: the answered value and the response's validated
/// trace identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentsComplete<T> {
    pub value: T,
    pub trace_id: String,
}

/// Which page of a list to read. Both fields are optional: no cursor reads
/// the first page, and no limit takes the service's default page size. A
/// cursor is opaque and passed back exactly as the previous page answered
/// it; the client never follows one on its own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageRequest {
    pub cursor: Option<String>,
    /// Items per page, 1 to `MAXIMUM_PAGE_SIZE`.
    pub limit: Option<u32>,
}

/// Released content whose SHA-256 digest matched the one the caller
/// expected. `Debug` names the media type and length, never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct DocumentContent {
    /// The `Content-Type` the content was released with.
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for DocumentContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentContent")
            .field("media_type", &self.media_type)
            .field("length", &self.bytes.len())
            .finish()
    }
}

pub struct DocumentsClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    maximum_response_bytes: u64,
    maximum_download_bytes: u64,
}

impl fmt::Debug for DocumentsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentsClient")
            .field("base_url", &"<validated service URL>")
            .finish_non_exhaustive()
    }
}

impl DocumentsClient {
    pub fn new(config: DocumentsClientConfig) -> Result<Self, DocumentsClientError> {
        let base_url = config.validate()?;
        let http = build_client(OutboundOptions {
            request_timeout: config.attempt_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| DocumentsClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            maximum_response_bytes: config.maximum_response_bytes,
            maximum_download_bytes: config.maximum_download_bytes,
        })
    }

    /// Whether the process answers at all.
    pub async fn health(&self) -> Result<DocumentsComplete<()>, DocumentsClientError> {
        let url = self.url(HEALTH_PATH, &[])?;
        let response =
            self.http
                .get(url)
                .send()
                .await
                .map_err(|error| DocumentsClientError::Transport {
                    kind: send_failure_kind(&error),
                })?;
        let status = response.status();
        validate_response_headers(response.headers())
            .map_err(|_| protocol(status, DocumentsProtocolFailure::HeaderBounds, None))?;
        if status != StatusCode::OK {
            return Err(problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        // The health answer has no body, so any byte is a protocol failure
        // rather than a response the caller's bound was too small for.
        match read_bounded(response, 0).await {
            Ok(_) => {}
            Err(
                BoundedReadError::ContentLengthExceeded { .. }
                | BoundedReadError::BodyTooLarge { .. },
            ) => {
                return Err(protocol(
                    status,
                    DocumentsProtocolFailure::Body,
                    Some(trace_id),
                ));
            }
            Err(error) => {
                return Err(DocumentsClientError::Transport {
                    kind: read_failure_kind(&error),
                })
            }
        }
        Ok(DocumentsComplete {
            value: (),
            trace_id,
        })
    }

    /// Reserve one document and the upload of its single version, under the
    /// caller's idempotency key. The service answers `201 Created` with the
    /// reservation, which names the upload `upload_content` sends the
    /// content to. The digest, length, and media type declared here are the
    /// ones the content must match.
    ///
    /// The caller chooses the key; the client never invents one. Each call
    /// is one exchange, and the client never resends it. An error for which
    /// `DocumentsClientError::is_outcome_unknown` is true may still have
    /// reserved the document: recover by sending the same request under the
    /// same key, which the service replays, never under a new key. A key
    /// that is empty, longer than 128 bytes, or carries a byte outside
    /// visible ASCII is refused before a request is sent.
    pub async fn reserve_document(
        &self,
        token: &BearerToken,
        idempotency_key: &str,
        request: &ReserveDocumentRequest,
    ) -> Result<DocumentsComplete<ReservationView>, DocumentsClientError> {
        require_idempotency_key(idempotency_key)?;
        let body = serde_json::to_vec(request).map_err(|_| {
            DocumentsClientError::invalid_request("the reservation could not be encoded")
        })?;
        let request = self
            .authorized(self.http.post(self.url(DOCUMENTS_PATH, &[])?), token)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .body(body);
        self.json_answer(request, StatusCode::CREATED).await
    }

    /// One page of the documents the caller holds in custody or reserved,
    /// oldest first.
    pub async fn list_documents(
        &self,
        token: &BearerToken,
        page: &PageRequest,
    ) -> Result<DocumentsComplete<DocumentPage>, DocumentsClientError> {
        let url = self.page_url(DOCUMENTS_PATH, &[], page)?;
        self.json_answer(self.authorized(self.http.get(url), token), StatusCode::OK)
            .await
    }

    /// One document as the caller may read it. `document_id` is the
    /// identifier the service answered, in its lowercase hyphenated UUID
    /// form; any other value is refused before a request is sent.
    pub async fn document(
        &self,
        token: &BearerToken,
        document_id: &str,
    ) -> Result<DocumentsComplete<DocumentView>, DocumentsClientError> {
        require_id(
            document_id,
            "the document identifier is not a lowercase hyphenated UUID",
        )?;
        let url = self.url(DOCUMENT_PATH, &[document_id])?;
        self.json_answer(self.authorized(self.http.get(url), token), StatusCode::OK)
            .await
    }

    /// Send the content of a reserved upload. The upload, the media type
    /// sent as `Content-Type`, and the length sent as `Content-Length` all
    /// come from the reservation, so the content cannot be sent under
    /// different terms than it was reserved with. The service checks the
    /// content against the digest the reservation declared and answers the
    /// document as the upload left it.
    ///
    /// A streamed body is sent as it is produced; one that yields a
    /// different number of bytes than reserved ends the exchange. An
    /// in-memory body of a different length, or a reservation whose upload
    /// path names no upload, is refused before a request is sent. The client
    /// never resends an upload: on an unknown outcome, read the document to
    /// learn whether the content arrived.
    pub async fn upload_content(
        &self,
        token: &BearerToken,
        reservation: &ReservationView,
        body: UploadBody,
    ) -> Result<DocumentsComplete<DocumentView>, DocumentsClientError> {
        let upload_id = upload_id(&reservation.upload_path)?;
        let version = &reservation.document.version;
        if !is_visible_ascii(&version.media_type) {
            return Err(DocumentsClientError::invalid_request(
                "the reserved media type is not a sendable Content-Type",
            ));
        }
        if body
            .as_bytes()
            .is_some_and(|bytes| bytes.len() as u64 != version.length)
        {
            return Err(DocumentsClientError::invalid_request(
                "the content length differs from the reserved length",
            ));
        }
        let url = self.url(UPLOAD_CONTENT_PATH, &[upload_id])?;
        let request = self
            .authorized(self.http.put(url), token)
            .header(CONTENT_TYPE, version.media_type.as_str())
            .header(CONTENT_LENGTH, version.length)
            .body(body);
        self.json_answer(request, StatusCode::OK).await
    }

    /// Download the content of one document version and check it against
    /// `expected_digest`, the version's `expectedDigest` as the caller read
    /// it. The content is read whole, under
    /// `DocumentsClientConfig::with_maximum_download_bytes`, and hashed before
    /// any of it is returned: content that does not match is a
    /// `DocumentsProtocolFailure::ContentDigest` failure, and the caller
    /// receives none of its bytes.
    ///
    /// Seeing a document does not entitle a caller to its content: the
    /// system that reserved a document it holds for someone else may read
    /// the document but is refused the download with
    /// `ProblemCode::ProfileNotAuthorized`.
    pub async fn download_content(
        &self,
        token: &BearerToken,
        document_id: &str,
        version_id: &str,
        expected_digest: &Digest,
    ) -> Result<DocumentsComplete<DocumentContent>, DocumentsClientError> {
        require_id(
            document_id,
            "the document identifier is not a lowercase hyphenated UUID",
        )?;
        require_id(
            version_id,
            "the version identifier is not a lowercase hyphenated UUID",
        )?;
        let url = self.url(DOCUMENT_CONTENT_PATH, &[document_id, version_id])?;
        let request = self
            .http
            .get(url)
            .header(AUTHORIZATION, token.authorization_header_value());
        let response = self.send(request).await?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        let Some(media_type) = single_header_text(response.headers()) else {
            return Err(protocol(
                status,
                DocumentsProtocolFailure::MediaType,
                Some(trace_id),
            ));
        };
        let bytes = read_bounded(response, self.maximum_download_bytes)
            .await
            .map_err(|error| DocumentsClientError::Transport {
                kind: read_failure_kind(&error),
            })?;
        if hex::encode(Sha256::digest(&bytes)) != expected_digest.hex() {
            return Err(protocol(
                status,
                DocumentsProtocolFailure::ContentDigest,
                Some(trace_id),
            ));
        }
        Ok(DocumentsComplete {
            value: DocumentContent { media_type, bytes },
            trace_id,
        })
    }

    /// Issue a grant releasing one exact version of a document to one named
    /// recipient, under the caller's idempotency key. The grantee names a
    /// subject and an actor kind; a caller of another kind with the same
    /// subject is not released anything. The service answers
    /// `201 Created` with the grant; a replay under the same key answers the
    /// grant as it stands now. The key is checked, and an unknown outcome is
    /// left to the caller to recover under the same key, exactly as for
    /// `reserve_document`; `document_id` is checked as `document` checks it.
    pub async fn issue_grant(
        &self,
        token: &BearerToken,
        idempotency_key: &str,
        document_id: &str,
        request: &IssueGrantRequest,
    ) -> Result<DocumentsComplete<DocumentGrantView>, DocumentsClientError> {
        require_idempotency_key(idempotency_key)?;
        require_id(
            document_id,
            "the document identifier is not a lowercase hyphenated UUID",
        )?;
        let body = serde_json::to_vec(request)
            .map_err(|_| DocumentsClientError::invalid_request("the grant could not be encoded"))?;
        let request = self
            .authorized(
                self.http
                    .post(self.url(DOCUMENT_GRANTS_PATH, &[document_id])?),
                token,
            )
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .body(body);
        self.json_answer(request, StatusCode::CREATED).await
    }

    /// One page of the grants issued on one document, oldest first.
    pub async fn document_grants(
        &self,
        token: &BearerToken,
        document_id: &str,
        page: &PageRequest,
    ) -> Result<DocumentsComplete<DocumentGrantPage>, DocumentsClientError> {
        require_id(
            document_id,
            "the document identifier is not a lowercase hyphenated UUID",
        )?;
        let url = self.page_url(DOCUMENT_GRANTS_PATH, &[document_id], page)?;
        self.json_answer(self.authorized(self.http.get(url), token), StatusCode::OK)
            .await
    }

    /// One page of the grants that name the caller as recipient, oldest
    /// first.
    pub async fn received_grants(
        &self,
        token: &BearerToken,
        page: &PageRequest,
    ) -> Result<DocumentsComplete<DocumentGrantPage>, DocumentsClientError> {
        let url = self.page_url(GRANTS_PATH, &[], page)?;
        self.json_answer(self.authorized(self.http.get(url), token), StatusCode::OK)
            .await
    }

    /// Revoke one grant and answer it as the revocation left it. The client
    /// never resends a revocation: on an unknown outcome, read the grant
    /// list to learn where it stands. `grant_id` is checked as `document`
    /// checks a document identifier.
    pub async fn revoke_grant(
        &self,
        token: &BearerToken,
        grant_id: &str,
    ) -> Result<DocumentsComplete<DocumentGrantView>, DocumentsClientError> {
        require_id(
            grant_id,
            "the grant identifier is not a lowercase hyphenated UUID",
        )?;
        let url = self.url(GRANT_PATH, &[grant_id])?;
        self.json_answer(
            self.authorized(self.http.delete(url), token),
            StatusCode::OK,
        )
        .await
    }

    /// Ask, as the document's custodian, for its erasure, and answer the
    /// document as the request left it. Release stops at once and every
    /// grant on the document is revoked. The route takes no idempotency key
    /// because it is idempotent by design: only the first request moves
    /// anything, and a repeat answers the document as it stands. A retry
    /// after an unknown outcome is therefore safe, and stays the caller's
    /// decision; the client never resends it. A caller who sees the document
    /// without being its custodian is answered 403 `ProfileNotAuthorized`,
    /// and one who cannot see it 404 `ResourceNotFound`. `document_id` is
    /// checked as `document` checks it.
    pub async fn request_erasure(
        &self,
        token: &BearerToken,
        document_id: &str,
    ) -> Result<DocumentsComplete<DocumentView>, DocumentsClientError> {
        require_id(
            document_id,
            "the document identifier is not a lowercase hyphenated UUID",
        )?;
        let url = self.url(DOCUMENT_ERASURE_PATH, &[document_id])?;
        self.json_answer(self.authorized(self.http.post(url), token), StatusCode::OK)
            .await
    }

    /// The document policies the caller may place documents under, with
    /// the restrictions to check before reserving.
    pub async fn policies(
        &self,
        token: &BearerToken,
    ) -> Result<DocumentsComplete<DocumentPolicyList>, DocumentsClientError> {
        let url = self.url(POLICIES_PATH, &[])?;
        self.json_answer(self.authorized(self.http.get(url), token), StatusCode::OK)
            .await
    }

    /// The URL of one route under the deployment prefix, with each `{name}`
    /// segment of the route taking the next of `values` in order.
    fn url(&self, route: &str, values: &[&str]) -> Result<Url, DocumentsClientError> {
        let mut values = values.iter();
        let segments = route_segments(route)
            .map(|segment| match segment {
                RouteSegment::Literal(literal) => Some(literal),
                RouteSegment::Placeholder => values.next().copied(),
            })
            .collect::<Option<Vec<_>>>();
        let segments = segments
            .filter(|_| values.next().is_none())
            .ok_or_else(|| {
                DocumentsClientError::configuration("the route does not take these values")
            })?;
        append_path_segments(self.base_url.as_url(), &segments)
            .map_err(|_| DocumentsClientError::configuration("the service base URL is not usable"))
    }

    fn page_url(
        &self,
        route: &str,
        values: &[&str],
        page: &PageRequest,
    ) -> Result<Url, DocumentsClientError> {
        if page
            .limit
            .is_some_and(|limit| !(1..=MAXIMUM_PAGE_SIZE).contains(&limit))
        {
            return Err(DocumentsClientError::invalid_request(
                "the page limit is not between 1 and the maximum page size",
            ));
        }
        let mut url = self.url(route, values)?;
        if page.cursor.is_some() || page.limit.is_some() {
            let mut query = url.query_pairs_mut();
            if let Some(cursor) = &page.cursor {
                query.append_pair("cursor", cursor);
            }
            if let Some(limit) = page.limit {
                query.append_pair("limit", &limit.to_string());
            }
        }
        Ok(url)
    }

    fn authorized(
        &self,
        request: reqwest::RequestBuilder,
        token: &BearerToken,
    ) -> reqwest::RequestBuilder {
        request
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE)
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Response, DocumentsClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| DocumentsClientError::Transport {
                kind: send_failure_kind(&error),
            })?;
        validate_response_headers(response.headers()).map_err(|_| {
            protocol(
                response.status(),
                DocumentsProtocolFailure::HeaderBounds,
                None,
            )
        })?;
        Ok(response)
    }

    async fn json_answer<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        expected: StatusCode,
    ) -> Result<DocumentsComplete<T>, DocumentsClientError> {
        let response = self.send(request).await?;
        self.json_response(response, expected).await
    }

    async fn json_response<T: DeserializeOwned>(
        &self,
        response: Response,
        expected: StatusCode,
    ) -> Result<DocumentsComplete<T>, DocumentsClientError> {
        let status = response.status();
        if status != expected {
            return Err(problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
            return Err(protocol(
                status,
                DocumentsProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let body = read_bounded(response, self.maximum_response_bytes)
            .await
            .map_err(|error| DocumentsClientError::Transport {
                kind: read_failure_kind(&error),
            })?;
        let value = serde_json::from_slice(&body).map_err(|_| {
            protocol(
                status,
                DocumentsProtocolFailure::Body,
                Some(trace_id.clone()),
            )
        })?;
        Ok(DocumentsComplete { value, trace_id })
    }
}

/// Refuse, before any request, an idempotency key the service would refuse:
/// it must be 1 to 128 bytes of visible ASCII.
fn require_idempotency_key(value: &str) -> Result<(), DocumentsClientError> {
    if (1..=MAXIMUM_IDEMPOTENCY_KEY_BYTES).contains(&value.len())
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        Ok(())
    } else {
        Err(DocumentsClientError::invalid_request(
            "the idempotency key is not 1 to 128 visible ASCII characters",
        ))
    }
}

/// Refuse, before any request, an identifier that is not a UUID in the
/// lowercase hyphenated form the service answers identifiers in.
fn require_id(value: &str, refusal: &'static str) -> Result<(), DocumentsClientError> {
    if is_id(value) {
        Ok(())
    } else {
        Err(DocumentsClientError::invalid_request(refusal))
    }
}

fn is_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

/// The upload a reservation's `uploadPath` names. The path is read only for
/// its upload identifier; the request goes to that upload under the
/// configured service URL, deployment prefix included.
enum RouteSegment<'a> {
    Literal(&'a str),
    Placeholder,
}

/// The segments of a route template such as `/v1/documents/{documentId}`.
fn route_segments(route: &str) -> impl Iterator<Item = RouteSegment<'_>> {
    route.trim_start_matches('/').split('/').map(|segment| {
        if segment.starts_with('{') && segment.ends_with('}') {
            RouteSegment::Placeholder
        } else {
            RouteSegment::Literal(segment)
        }
    })
}

/// The upload id an upload path names, when the path is the upload content
/// route with exactly one id in its placeholder.
fn upload_id(path: &str) -> Result<&str, DocumentsClientError> {
    let mut id = None;
    let mut route = route_segments(UPLOAD_CONTENT_PATH);
    let mut given = path.strip_prefix('/').unwrap_or_default().split('/');
    let matches = loop {
        match (route.next(), given.next()) {
            (None, None) => break true,
            (Some(RouteSegment::Literal(literal)), Some(segment)) if literal == segment => {}
            (Some(RouteSegment::Placeholder), Some(segment)) if is_id(segment) => {
                id = Some(segment);
            }
            _ => break false,
        }
    };
    id.filter(|_| matches).ok_or_else(|| {
        DocumentsClientError::invalid_request(
            "the reservation's upload path does not name an upload",
        )
    })
}

fn is_visible_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// The single `Content-Type` value of an answer, when it has exactly one and
/// that value is visible ASCII.
fn single_header_text(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|text| is_visible_ascii(text))
            .map(str::to_owned),
        _ => None,
    }
}

async fn problem_or_status(response: Response) -> DocumentsClientError {
    let status = response.status();
    let trace = response_trace(status, response.headers()).ok();
    if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
        return protocol(status, DocumentsProtocolFailure::Status, trace);
    }
    let body = match read_bounded(response, MAXIMUM_PROBLEM_BYTES).await {
        Ok(value) => value,
        Err(error) => {
            return DocumentsClientError::Transport {
                kind: read_failure_kind(&error),
            }
        }
    };
    let Ok(document) = ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES as usize) else {
        return protocol(status, DocumentsProtocolFailure::Problem, trace);
    };
    domain_problem(status, trace, &document)
}

/// Decide between a typed product problem and a protocol failure. A product
/// problem requires the document's status to equal the response status, its
/// code to be in the closed vocabulary and pin that same status, the
/// response trace to match the document's, and the type URI to equal the
/// pinned definition. The title and detail are not compared: the caller
/// reads its own pinned copies.
fn domain_problem(
    status: StatusCode,
    header_trace: Option<String>,
    document: &ProblemDocument,
) -> DocumentsClientError {
    let Some(code) = ProblemCode::from_code(&document.code) else {
        return protocol(status, DocumentsProtocolFailure::Problem, header_trace);
    };
    if document.status != status.as_u16()
        || code.http_status() != status.as_u16()
        || header_trace.as_deref() != Some(document.trace_id.as_str())
        || document.type_uri != type_uri(code.code())
    {
        return protocol(status, DocumentsProtocolFailure::Problem, header_trace);
    }
    DocumentsClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id: header_trace,
    }
}

fn response_trace(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<String, DocumentsClientError> {
    response_trace_id(headers)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| protocol(status, DocumentsProtocolFailure::TraceContext, None))
}

fn exact_media_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == expected.as_bytes()
    )
}

fn protocol(
    status: StatusCode,
    failure: DocumentsProtocolFailure,
    trace_id: Option<String>,
) -> DocumentsClientError {
    DocumentsClientError::Protocol {
        status: status.as_u16(),
        failure,
        trace_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_withholds_url_and_certificate_material() {
        let config = DocumentsClientConfig::new(
            Url::parse("https://secret.example.invalid/private").expect("fixture URL"),
        )
        .with_user_agent("secret-agent")
        .with_trusted_root_certificates(b"secret-certificate".to_vec());
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret.example"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret-agent"));
        assert!(!debug.contains("secret-certificate"));
    }

    #[test]
    fn debug_withholds_downloaded_content() {
        let content = DocumentContent {
            media_type: "application/pdf".to_owned(),
            bytes: b"secret-content".to_vec(),
        };
        let debug = format!("{content:?}");
        assert!(debug.contains("application/pdf"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn only_a_reserved_upload_path_names_an_upload() {
        let id = "8b3c4d5e-6f7a-4b2c-9d3e-4f5a6b7c8d9e";
        assert_eq!(
            upload_id(&format!("/v1/uploads/{id}/content")).ok(),
            Some(id)
        );
        for path in [
            String::new(),
            format!("uploads/{id}/content"),
            format!("/uploads/{id}/content"),
            format!("/v1/uploads/{id}/content/"),
            format!("/v1/uploads/{id}/../content"),
            format!("/v1/uploads/{}/content", id.to_ascii_uppercase()),
            format!("//elsewhere.example/uploads/{id}/content"),
        ] {
            assert!(upload_id(&path).is_err(), "{path}");
        }
    }

    #[test]
    fn a_route_takes_exactly_its_placeholder_values_in_order() {
        let client = DocumentsClient::new(DocumentsClientConfig::new(
            Url::parse("https://documents.example.invalid/store/").expect("fixture URL"),
        ))
        .expect("client");
        let url = client
            .url(DOCUMENT_CONTENT_PATH, &["d-1", "v-2"])
            .expect("route URL");
        assert_eq!(
            url.as_str(),
            "https://documents.example.invalid/store/v1/documents/d-1/versions/v-2/content"
        );
        assert!(client.url(DOCUMENT_CONTENT_PATH, &["d-1"]).is_err());
        assert!(client.url(DOCUMENTS_PATH, &["d-1"]).is_err());
    }

    #[test]
    fn configuration_bounds_are_enforced_before_any_client_exists() {
        let url = Url::parse("https://documents.example.invalid/").expect("fixture URL");
        for config in [
            DocumentsClientConfig::new(url.clone()).with_attempt_timeout(Duration::ZERO),
            DocumentsClientConfig::new(url.clone()).with_connect_timeout(Duration::ZERO),
            DocumentsClientConfig::new(url.clone()).with_trusted_root_certificates(vec![
                0;
                MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES
                    + 1
            ]),
            DocumentsClientConfig::new(
                Url::parse("https://user:pass@documents.example.invalid/").expect("fixture URL"),
            ),
            DocumentsClientConfig::new(url.clone()).with_maximum_response_bytes(0),
            DocumentsClientConfig::new(url.clone())
                .with_maximum_response_bytes(MAXIMUM_RESPONSE_BYTES + 1),
            DocumentsClientConfig::new(url.clone()).with_maximum_download_bytes(0),
            DocumentsClientConfig::new(url.clone())
                .with_maximum_download_bytes(MAXIMUM_DOWNLOAD_BYTES + 1),
        ] {
            assert!(
                matches!(
                    config.validate(),
                    Err(DocumentsClientError::Configuration { .. })
                ),
                "{config:?}"
            );
        }
        assert!(DocumentsClientConfig::new(url.clone())
            .with_maximum_response_bytes(MAXIMUM_RESPONSE_BYTES)
            .with_maximum_download_bytes(MAXIMUM_DOWNLOAD_BYTES)
            .validate()
            .is_ok());
        assert!(DocumentsClientConfig::new(url).validate().is_ok());
    }
}

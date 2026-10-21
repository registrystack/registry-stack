// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::time::Duration;

use registry_documents_core::{
    type_uri, DocumentGrantPage, DocumentGrantView, DocumentPage, DocumentPolicyList, DocumentView,
    IssueGrantRequest, ProblemCode, ReservationView, ReserveDocumentRequest, HEALTH_PATH,
    MAXIMUM_PAGE_SIZE,
};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, classify_keyed_attempt, read_failure_kind, retry_keyed_mutation,
    send_failure_kind, BearerToken, KeyedMutationAttempt, OutboundOptions, RetryAfter,
    ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MUTATION_RETRIES, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_MUTATION_RETRIES, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
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

/// The header a creating request names its idempotency key in.
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
/// The longest idempotency key the service accepts.
const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;

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
    request_timeout: Duration,
    connect_timeout: Duration,
    user_agent: Option<String>,
    trusted_root_certificates: Option<Vec<u8>>,
    max_response_bytes: u64,
    max_download_bytes: u64,
    max_mutation_retries: u8,
}

impl DocumentsClientConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
            max_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
            max_download_bytes: DEFAULT_MAXIMUM_DOWNLOAD_BYTES,
            max_mutation_retries: DEFAULT_MUTATION_RETRIES,
        }
    }

    #[must_use]
    pub fn with_request_timeout(mut self, value: Duration) -> Self {
        self.request_timeout = value;
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
    pub fn with_max_response_bytes(mut self, value: u64) -> Self {
        self.max_response_bytes = value;
        self
    }

    /// The most bytes released content may carry: 16 MiB by default, at most
    /// 64 MiB. A download is held in memory until its digest is checked, so
    /// this bound is also the most memory one download may take.
    #[must_use]
    pub fn with_max_download_bytes(mut self, value: u64) -> Self {
        self.max_download_bytes = value;
        self
    }

    /// How many times a reservation or a grant whose outcome is unknown is
    /// resent under the same idempotency key: 2 by default and at most;
    /// 0 disables the resend.
    #[must_use]
    pub fn with_max_mutation_retries(mut self, value: u8) -> Self {
        self.max_mutation_retries = value;
        self
    }

    fn validate(&self) -> Result<ServiceBaseUrl, DocumentsClientError> {
        let base_url = ServiceBaseUrl::new(self.base_url.clone()).map_err(|_| {
            DocumentsClientError::configuration("the service base URL is not usable")
        })?;
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(DocumentsClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAXIMUM_RESPONSE_BYTES {
            return Err(DocumentsClientError::configuration(
                "the response byte bound must be between 1 byte and 16 MiB",
            ));
        }
        if self.max_download_bytes == 0 || self.max_download_bytes > MAXIMUM_DOWNLOAD_BYTES {
            return Err(DocumentsClientError::configuration(
                "the download byte bound must be between 1 byte and 64 MiB",
            ));
        }
        if self.max_mutation_retries > MAXIMUM_MUTATION_RETRIES {
            return Err(DocumentsClientError::configuration(
                "the mutation retry count exceeds the accepted maximum",
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
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("user_agent_present", &self.user_agent.is_some())
            .field(
                "trusted_root_certificates_present",
                &self.trusted_root_certificates.is_some(),
            )
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_download_bytes", &self.max_download_bytes)
            .field("max_mutation_retries", &self.max_mutation_retries)
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
    max_response_bytes: u64,
    max_download_bytes: u64,
    max_mutation_retries: u8,
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
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| DocumentsClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
            max_download_bytes: config.max_download_bytes,
            max_mutation_retries: config.max_mutation_retries,
        })
    }

    /// Whether the process answers at all.
    pub async fn health(&self) -> Result<DocumentsComplete<()>, DocumentsClientError> {
        let segments = HEALTH_PATH
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        let url = append_path_segments(self.base_url.as_url(), &segments).map_err(|_| {
            DocumentsClientError::configuration("the service base URL is not usable")
        })?;
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
    /// The caller chooses the key; the client never invents one. When the
    /// outcome is unknown, after a timeout or broken exchange or on a 5xx
    /// answer, the client resends the identical request under the same key,
    /// at most `DocumentsClientConfig::with_max_mutation_retries` times. An
    /// error for which `DocumentsClientError::is_outcome_unknown` is true
    /// may still have reserved the document: recover with the same key and
    /// request, never a new key. A key that is empty, longer than 128 bytes,
    /// or carries a byte outside visible ASCII is refused before a request
    /// is sent.
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
            .authorized(self.http.post(self.url(&["documents"])?), token)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .body(body);
        self.send_keyed_json(request, StatusCode::CREATED).await
    }

    /// One page of the documents the caller holds in custody or reserved,
    /// oldest first.
    pub async fn list_documents(
        &self,
        token: &BearerToken,
        page: &PageRequest,
    ) -> Result<DocumentsComplete<DocumentPage>, DocumentsClientError> {
        let url = self.page_url(&["documents"], page)?;
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
        let url = self.url(&["documents", document_id])?;
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
        let url = self.url(&["uploads", upload_id, "content"])?;
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
    /// `DocumentsClientConfig::with_max_download_bytes`, and hashed before
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
        let url = self.url(&["documents", document_id, "versions", version_id, "content"])?;
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
        let bytes = read_bounded(response, self.max_download_bytes)
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
    /// grant as it stands now. The key is checked and an unknown outcome is
    /// resent exactly as `reserve_document` does; `document_id` is checked
    /// as `document` checks it.
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
                    .post(self.url(&["documents", document_id, "grants"])?),
                token,
            )
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .body(body);
        self.send_keyed_json(request, StatusCode::CREATED).await
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
        let url = self.page_url(&["documents", document_id, "grants"], page)?;
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
        let url = self.page_url(&["document-grants"], page)?;
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
        let url = self.url(&["document-grants", grant_id])?;
        self.json_answer(
            self.authorized(self.http.delete(url), token),
            StatusCode::OK,
        )
        .await
    }

    /// The document policies the caller may place documents under, with
    /// the restrictions to check before reserving.
    pub async fn policies(
        &self,
        token: &BearerToken,
    ) -> Result<DocumentsComplete<DocumentPolicyList>, DocumentsClientError> {
        let url = self.url(&["document-policies"])?;
        self.json_answer(self.authorized(self.http.get(url), token), StatusCode::OK)
            .await
    }

    fn url(&self, segments: &[&str]) -> Result<Url, DocumentsClientError> {
        append_path_segments(self.base_url.as_url(), segments)
            .map_err(|_| DocumentsClientError::configuration("the service base URL is not usable"))
    }

    fn page_url(&self, segments: &[&str], page: &PageRequest) -> Result<Url, DocumentsClientError> {
        if page
            .limit
            .is_some_and(|limit| !(1..=MAXIMUM_PAGE_SIZE).contains(&limit))
        {
            return Err(DocumentsClientError::invalid_request(
                "the page limit is not between 1 and the maximum page size",
            ));
        }
        let mut url = self.url(segments)?;
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

    /// Send one idempotency-keyed request, resending the identical request
    /// under the same key while its outcome stays unknown, at most the
    /// configured number of times.
    async fn send_keyed_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        expected: StatusCode,
    ) -> Result<DocumentsComplete<T>, DocumentsClientError> {
        let request = &request;
        retry_keyed_mutation(self.max_mutation_retries, || async move {
            let Some(attempt) = request.try_clone() else {
                return KeyedMutationAttempt::Settled(Err(DocumentsClientError::invalid_request(
                    "the request could not be prepared for sending",
                )));
            };
            let response = match self.send(attempt).await {
                Ok(response) => response,
                Err(error) => return keyed_attempt(Err(error), None, RetryAfter::Absent),
            };
            let status = response.status();
            let retry_after = RetryAfter::from_headers(response.headers());
            keyed_attempt(
                self.json_response(response, expected).await,
                Some(status),
                retry_after,
            )
        })
        .await
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
        let body = read_bounded(response, self.max_response_bytes)
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

/// Classify one attempt of an idempotency-keyed request for the same-key
/// resend, with the shared rule. `status` and `retry_after` describe the
/// answer, when one arrived.
fn keyed_attempt<T>(
    result: Result<T, DocumentsClientError>,
    status: Option<StatusCode>,
    retry_after: RetryAfter,
) -> KeyedMutationAttempt<T, DocumentsClientError> {
    classify_keyed_attempt(
        result,
        status,
        retry_after,
        DocumentsClientError::is_outcome_unknown,
        DocumentsClientError::resend_may_settle,
    )
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
fn upload_id(path: &str) -> Result<&str, DocumentsClientError> {
    path.strip_prefix("/uploads/")
        .and_then(|rest| rest.strip_suffix("/content"))
        .filter(|id| is_id(id))
        .ok_or_else(|| {
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
        assert_eq!(upload_id(&format!("/uploads/{id}/content")).ok(), Some(id));
        for path in [
            String::new(),
            format!("uploads/{id}/content"),
            format!("/uploads/{id}/content/"),
            format!("/uploads/{id}/../content"),
            format!("/uploads/{}/content", id.to_ascii_uppercase()),
            format!("//elsewhere.example/uploads/{id}/content"),
        ] {
            assert!(upload_id(&path).is_err(), "{path}");
        }
    }

    #[test]
    fn configuration_bounds_are_enforced_before_any_client_exists() {
        let url = Url::parse("https://documents.example.invalid/").expect("fixture URL");
        for config in [
            DocumentsClientConfig::new(url.clone()).with_request_timeout(Duration::ZERO),
            DocumentsClientConfig::new(url.clone()).with_connect_timeout(Duration::ZERO),
            DocumentsClientConfig::new(url.clone()).with_trusted_root_certificates(vec![
                0;
                MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES
                    + 1
            ]),
            DocumentsClientConfig::new(
                Url::parse("https://user:pass@documents.example.invalid/").expect("fixture URL"),
            ),
            DocumentsClientConfig::new(url.clone()).with_max_response_bytes(0),
            DocumentsClientConfig::new(url.clone())
                .with_max_response_bytes(MAXIMUM_RESPONSE_BYTES + 1),
            DocumentsClientConfig::new(url.clone()).with_max_download_bytes(0),
            DocumentsClientConfig::new(url.clone())
                .with_max_download_bytes(MAXIMUM_DOWNLOAD_BYTES + 1),
            DocumentsClientConfig::new(url.clone())
                .with_max_mutation_retries(MAXIMUM_MUTATION_RETRIES + 1),
        ] {
            assert!(
                matches!(
                    config.validate(),
                    Err(DocumentsClientError::Configuration { .. })
                ),
                "{config:?}"
            );
        }
        for retries in 0..=MAXIMUM_MUTATION_RETRIES {
            assert!(DocumentsClientConfig::new(url.clone())
                .with_max_mutation_retries(retries)
                .validate()
                .is_ok());
        }
        assert!(DocumentsClientConfig::new(url.clone())
            .with_max_response_bytes(MAXIMUM_RESPONSE_BYTES)
            .with_max_download_bytes(MAXIMUM_DOWNLOAD_BYTES)
            .validate()
            .is_ok());
        assert!(DocumentsClientConfig::new(url).validate().is_ok());
    }
}

//! The HTTP client: one request, one offline verification.
//!
//! Every exchange here is bounded and unretried. The only judgement the client
//! makes about a response is the one the portable verifier makes for it, against
//! the policy the caller closed before the request existed.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use registry_evidence_verifier::{
    model::{
        Evidence, EvidenceRequestBatchResponse, EvidenceRequestBatchResponseItem, JwksDocument,
    },
    verifier::ExpectedSubjectDocument,
    EVIDENCE_REQUEST_BATCH_MEDIA_TYPE, EVIDENCE_REQUEST_BATCH_SCHEMA_V1,
};
use registry_platform_httputil::{
    read_bounded, retry_after_seconds, validate_response_headers, FetchUrlPolicy,
};
use reqwest::{
    header::{
        HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG,
        IF_NONE_MATCH,
    },
    Method, StatusCode,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

#[cfg(test)]
use crate::problem::TRACEPARENT_HEADER;
#[cfg(test)]
use reqwest::header::RETRY_AFTER;

use crate::{
    batch::{SdJwtVcBatchResponse, MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES},
    config::EvidenceClientConfig,
    definitions::{EvidenceDefinitionsDocument, EVIDENCE_DEFINITIONS_SCHEMA_V1},
    error::EvidenceClientError,
    outbound::{self, OutboundOptions},
    prepare::{
        EvidenceRequestSpec, HolderBoundRequestSpec, PreparedEvidenceRequest,
        PreparedHolderBoundRequest,
    },
    private_key_jwt::{PrivateKeyJwt, PrivateKeyJwtConfig},
    problem::{essence, map_problem},
    profile::{ContractsProfile, EvidenceClientProfile, TrustProfile},
    progressive::{
        progressive_result, select_definition, spec_from_definition, AudienceScopedRequest,
        EvidenceClientContracts, ProgressivePreparedRequest, VerifiedAudienceScopedEvidence,
    },
    request_batch::{
        EvidenceRequestBatchSpec, PreparedEvidenceRequestBatch, RawEvidenceRequestBatchResponse,
        VerifiedEvidenceRequestBatch, VerifiedEvidenceRequestBatchItem,
        MAX_EVIDENCE_REQUEST_BATCH_RESPONSE_BYTES,
    },
    response_format::EvidenceResponseFormat,
    retained::RetainedEvidenceVerification,
    token::TokenProvider,
};
use registry_platform_crypto::PrivateJwk;

/// Path of the Evidence request endpoint.
const EVIDENCE_PATH: &str = "v1/evidence";
/// Path of the ordered multi-subject Evidence request-batch endpoint.
const EVIDENCE_BATCH_PATH: &str = "v1/evidence/batch";
/// Path of the requester-scoped discovery endpoint.
const DEFINITIONS_PATH: &str = "v1/evidence-definitions";
/// Path of the published verification key set.
const JWKS_PATH: &str = ".well-known/evidence/jwks.json";

const JSON_MEDIA_TYPE: &str = "application/json";
const JWKS_MEDIA_TYPE: &str = "application/jwk-set+json";

/// Longest `Retry-After` wait this client reports as actionable.
///
/// The problem contract permits a wait only for bounded transient failures, and
/// states no value, so the bound is the client's own. `Retry-After` is a
/// response-controlled field: a caller that honors an unbounded one would stop
/// for as long as any hop on the path chose, and a wait of zero would invite an
/// immediate retry loop. A longer wait is not reported at all, which leaves the
/// caller its own backoff rather than an instruction it did not ask for.
pub const MAXIMUM_RETRY_AFTER_SECONDS: u64 = 60;

/// Whether an exchange carries the relying party's bearer credential.
///
/// Named rather than a boolean, so a call site states which of the two it means
/// instead of leaving the reader to recover it from a bare `true`.
enum Credential {
    Required,
    None,
}

/// A relying party's connection to one Evidence deployment.
pub struct EvidenceClient {
    config: EvidenceClientConfig,
    http: reqwest::Client,
    progressive: Option<Arc<ProgressiveClientState>>,
}

impl std::fmt::Debug for EvidenceClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceClient")
            .field("config", &self.config)
            .field("profile_driven", &self.progressive.is_some())
            .finish_non_exhaustive()
    }
}

struct ProgressiveClientState {
    profile: EvidenceClientProfile,
    private_key: PrivateJwk,
    cache: Mutex<Option<CachedServiceSnapshot>>,
}

struct CachedServiceSnapshot {
    value: ProgressiveServiceSnapshot,
    expires_at: Instant,
    stale_until: Instant,
}

#[derive(Clone)]
struct ProgressiveSnapshot {
    definitions: EvidenceDefinitionsDocument,
    jwks: JwksDocument,
    token_provider: Arc<dyn TokenProvider>,
}

#[derive(Clone)]
struct ProgressiveServiceSnapshot {
    protected: ProtectedResourceMetadata,
    authorization: AuthorizationServerMetadata,
    jwks: JwksDocument,
    token_provider: Arc<dyn TokenProvider>,
    protected_etag: Option<HeaderValue>,
    authorization_etag: Option<HeaderValue>,
    jwks_etag: Option<HeaderValue>,
    protected_cache_seconds: u64,
    authorization_cache_seconds: u64,
    jwks_cache_seconds: u64,
    cache_seconds: u64,
}

struct PublicDocument<T> {
    value: T,
    etag: Option<HeaderValue>,
    cache_seconds: u64,
}

#[derive(Clone, Deserialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    jwks_uri: String,
    bearer_methods_supported: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    token_endpoint: String,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

/// A signed response, read but not yet judged.
///
/// It exists so a relying party can retain the exact bytes it verified. Nothing
/// in it has been trusted yet.
#[derive(Clone)]
pub struct RawEvidenceResponse {
    body: Vec<u8>,
    trace_id: Option<String>,
}

impl RawEvidenceResponse {
    /// The signed response bytes, exactly as received.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The validated W3C trace identifier for this exchange.
    ///
    /// It is support correlation only, not an Evidence audit operation
    /// identity.
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
}

impl std::fmt::Debug for RawEvidenceResponse {
    /// The body is unverified, potentially subject-identifying material, so only
    /// its length and the correlation identifier are rendered.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawEvidenceResponse")
            .field("body_bytes", &self.body.len())
            .field("trace_id", &self.trace_id)
            .finish_non_exhaustive()
    }
}

/// A response that satisfied every expectation.
#[derive(Debug, Clone)]
pub struct VerifiedEvidence {
    pub(crate) evidence: Evidence,
    pub(crate) trace_id: Option<String>,
}

impl VerifiedEvidence {
    /// The verified payload.
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The validated W3C trace identifier for the exchange that produced this
    /// payload. It is support correlation only, not an Evidence audit operation
    /// identity.
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }

    /// The role-bound subject bindings this payload carries, as pinned
    /// expectations for later requests.
    ///
    /// Persist these after a first-use acceptance and pass them as
    /// [`SubjectExpectations::Pinned`] from then on. Once pinned, a response
    /// about a different subject fails verification instead of being accepted.
    #[must_use]
    pub fn pinned_subject_expectations(&self) -> Vec<ExpectedSubjectDocument> {
        self.evidence
            .subjects
            .iter()
            .map(|subject| ExpectedSubjectDocument {
                role: subject.role.clone(),
                binding: subject.binding.clone(),
            })
            .collect()
    }
}

impl EvidenceClient {
    /// Build a client for one deployment.
    ///
    /// The configuration must pin a key set. A configuration built by
    /// [`EvidenceClientConfig::without_verification`] is refused here, because
    /// every verification method on this type reads that key set, and a client
    /// that silently did not verify would be a far worse outcome than a refusal
    /// at construction. Such a configuration builds a
    /// [`NonVerifyingEvidenceClient`] instead.
    pub fn new(config: EvidenceClientConfig) -> Result<Self, EvidenceClientError> {
        if !config.verifies() {
            return Err(EvidenceClientError::configuration(
                "this client verifies, so its configuration must pin a key set",
            ));
        }
        Self::build(config)
    }

    /// Build the high-level client from a parsed application-owned profile.
    pub fn from_profile(profile: EvidenceClientProfile) -> Result<Self, EvidenceClientError> {
        let private_key = profile.load_private_key()?;
        Self::from_profile_with_key(profile, private_key)
    }

    /// Build from a profile while supplying secret-manager key material in memory.
    pub fn from_profile_with_key(
        profile: EvidenceClientProfile,
        private_key: PrivateJwk,
    ) -> Result<Self, EvidenceClientError> {
        profile.validate()?;
        let base_url = Url::parse(&profile.base_url).map_err(|_| {
            EvidenceClientError::configuration("the client profile is invalid or unavailable")
        })?;
        let config = EvidenceClientConfig::progressive(base_url)?;
        config.validate()?;
        let http = build_client(&config)?;
        Ok(Self {
            config,
            http,
            progressive: Some(Arc::new(ProgressiveClientState {
                profile,
                private_key,
                cache: Mutex::new(None),
            })),
        })
    }

    pub fn from_profile_path(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, EvidenceClientError> {
        Self::from_profile(EvidenceClientProfile::from_file(path)?)
    }

    pub fn from_profile_path_with_key(
        path: impl AsRef<std::path::Path>,
        private_key: PrivateJwk,
    ) -> Result<Self, EvidenceClientError> {
        Self::from_profile_with_key(EvidenceClientProfile::from_file(path)?, private_key)
    }

    /// Invalidate cached public metadata and acquire a fresh closed snapshot.
    pub async fn refresh_metadata(&self) -> Result<(), EvidenceClientError> {
        let state = self.progressive_state()?;
        let mut cache = state.cache.lock().await;
        let previous = cache.take();
        let snapshot = match self
            .acquire_service_snapshot(state, previous.as_ref().map(|value| &value.value))
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                *cache = previous;
                return Err(error);
            }
        };
        let now = Instant::now();
        let (expires_at, stale_until) = cache_deadlines(
            now,
            snapshot.cache_seconds,
            state.profile.maximum_metadata_cache_seconds,
        );
        *cache = Some(CachedServiceSnapshot {
            expires_at,
            stale_until,
            value: snapshot,
        });
        Ok(())
    }

    /// Discover, prepare, send once, and verify one audience-scoped result.
    pub async fn request(
        &self,
        request: AudienceScopedRequest,
    ) -> Result<VerifiedAudienceScopedEvidence, EvidenceClientError> {
        let state = self.progressive_state()?;
        let snapshot = self.progressive_snapshot(state).await?;
        let definition = select_definition(&snapshot.definitions, &request)?.clone();
        let spec = spec_from_definition(
            &snapshot.definitions,
            &definition,
            &request,
            state
                .profile
                .verification
                .maximum_assertion_lifetime_seconds,
            state.profile.verification.clock_skew_seconds,
        )?;
        let matched = request.binding_receipt.is_some();
        let client = EvidenceClient::new(EvidenceClientConfig::new(
            self.config.base_url.clone(),
            Arc::clone(&snapshot.token_provider),
            snapshot.jwks.clone(),
            Vec::new(),
        ))?;
        let prepared = client.prepare(spec)?;
        let raw = client.send(&prepared).await?;
        let verified = client.verify(&prepared, &raw)?;
        progressive_result(&definition, request.response_format, raw, verified, matched)
    }

    /// Fetch the requester-scoped, client-safe catalog candidate for review.
    pub async fn contracts_candidate(
        &self,
    ) -> Result<EvidenceClientContracts, EvidenceClientError> {
        let state = self.progressive_state()?;
        let snapshot = self.progressive_snapshot(state).await?;
        Ok(snapshot.definitions.into())
    }

    /// Prepare owner-only artifacts for a caller that will perform the single
    /// HTTP POST itself, while retaining the same offline verification context.
    pub async fn prepare_progressive(
        &self,
        request: AudienceScopedRequest,
    ) -> Result<ProgressivePreparedRequest, EvidenceClientError> {
        let state = self.progressive_state()?;
        let snapshot = self.progressive_snapshot(state).await?;
        let definition = select_definition(&snapshot.definitions, &request)?.clone();
        let spec = spec_from_definition(
            &snapshot.definitions,
            &definition,
            &request,
            state
                .profile
                .verification
                .maximum_assertion_lifetime_seconds,
            state.profile.verification.clock_skew_seconds,
        )?;
        let client = EvidenceClient::new(EvidenceClientConfig::new(
            self.config.base_url.clone(),
            Arc::clone(&snapshot.token_provider),
            snapshot.jwks.clone(),
            Vec::new(),
        ))?;
        let prepared = client.prepare(spec)?;
        let token = snapshot.token_provider.bearer_token().await?;
        let authorization = token
            .authorization_header_value()
            .to_str()
            .map_err(|_| metadata_protocol_failure())?
            .to_owned();
        Ok(ProgressivePreparedRequest {
            endpoint: client.endpoint(EVIDENCE_PATH)?.to_string(),
            accept: request.response_format.media_type().to_owned(),
            authorization,
            request_json: prepared.request_json()?,
            retained_verification: serde_json::to_vec(&client.retain_verification(&prepared))
                .map_err(|_| {
                    EvidenceClientError::configuration(
                        "the retained verification context could not be serialized",
                    )
                })?,
        })
    }

    fn progressive_state(&self) -> Result<&ProgressiveClientState, EvidenceClientError> {
        self.progressive.as_deref().ok_or_else(|| {
            EvidenceClientError::configuration("this operation requires a client profile")
        })
    }

    async fn progressive_snapshot(
        &self,
        state: &ProgressiveClientState,
    ) -> Result<ProgressiveSnapshot, EvidenceClientError> {
        let service = self.progressive_service_snapshot(state).await?;
        let definitions = match &state.profile.contracts {
            ContractsProfile::Reviewed { file } => state.profile.load_reviewed_contracts(file)?,
            ContractsProfile::Published => {
                let temporary = EvidenceClient::new(EvidenceClientConfig::new(
                    self.config.base_url.clone(),
                    Arc::clone(&service.token_provider),
                    service.jwks.clone(),
                    Vec::new(),
                ))?;
                temporary.discover().await?
            }
        };
        definitions.validate_for_progressive_request()?;
        validate_profile_expectations(&state.profile, &definitions)?;
        Ok(ProgressiveSnapshot {
            definitions,
            jwks: service.jwks,
            token_provider: service.token_provider,
        })
    }

    async fn progressive_service_snapshot(
        &self,
        state: &ProgressiveClientState,
    ) -> Result<ProgressiveServiceSnapshot, EvidenceClientError> {
        let mut cache = state.cache.lock().await;
        if let Some(cached) = cache
            .as_ref()
            .filter(|cached| cached.expires_at > Instant::now())
        {
            return Ok(cached.value.clone());
        }
        let snapshot = match self
            .acquire_service_snapshot(state, cache.as_ref().map(|value| &value.value))
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if let Some(cached) = cache
                    .as_ref()
                    .filter(|cached| cached.stale_until > Instant::now())
                {
                    return Ok(cached.value.clone());
                }
                return Err(error);
            }
        };
        let now = Instant::now();
        let (expires_at, stale_until) = cache_deadlines(
            now,
            snapshot.cache_seconds,
            state.profile.maximum_metadata_cache_seconds,
        );
        *cache = Some(CachedServiceSnapshot {
            value: snapshot.clone(),
            expires_at,
            stale_until,
        });
        Ok(snapshot)
    }

    async fn acquire_service_snapshot(
        &self,
        state: &ProgressiveClientState,
        previous: Option<&ProgressiveServiceSnapshot>,
    ) -> Result<ProgressiveServiceSnapshot, EvidenceClientError> {
        let fetch_policy = metadata_fetch_policy(&state.profile.trust);
        let resource_url = self.endpoint(".well-known/oauth-protected-resource")?;
        let protected = self
            .public_json(
                resource_url,
                JSON_MEDIA_TYPE,
                previous.map(|value| {
                    (
                        &value.protected,
                        value.protected_etag.as_ref(),
                        value.protected_cache_seconds,
                    )
                }),
                state.profile.maximum_metadata_cache_seconds,
                &fetch_policy,
            )
            .await?;
        if protected.value.resource != state.profile.base_url
            || protected.value.authorization_servers.len() != 1
            || protected.value.bearer_methods_supported != ["header"]
        {
            return Err(metadata_protocol_failure());
        }
        let announced_issuer = &protected.value.authorization_servers[0];
        let issuer = Url::parse(announced_issuer).map_err(|_| metadata_protocol_failure())?;
        validate_metadata_url(&issuer, &state.profile.trust)?;
        let metadata_url = metadata_endpoint(&issuer)?;
        let authorization = self
            .public_json(
                metadata_url,
                JSON_MEDIA_TYPE,
                previous.map(|value| {
                    (
                        &value.authorization,
                        value.authorization_etag.as_ref(),
                        value.authorization_cache_seconds,
                    )
                }),
                state.profile.maximum_metadata_cache_seconds,
                &fetch_policy,
            )
            .await?;
        if !authorization_server_metadata_is_compatible(&authorization.value, announced_issuer) {
            return Err(metadata_protocol_failure());
        }
        let token_endpoint = Url::parse(&authorization.value.token_endpoint)
            .map_err(|_| metadata_protocol_failure())?;
        validate_metadata_url(&token_endpoint, &state.profile.trust)?;
        let expected_jwks = self.endpoint(JWKS_PATH)?;
        let jwks_url =
            Url::parse(&protected.value.jwks_uri).map_err(|_| metadata_protocol_failure())?;
        if jwks_url != expected_jwks {
            return Err(metadata_protocol_failure());
        }
        let jwks = match &state.profile.trust {
            TrustProfile::PinnedJwks { file } => PublicDocument {
                value: state.profile.load_pinned_jwks(file)?,
                etag: None,
                cache_seconds: state.profile.maximum_metadata_cache_seconds,
            },
            TrustProfile::HttpsDiscovery | TrustProfile::LocalLoopbackDiscovery => {
                self.public_json(
                    jwks_url,
                    JWKS_MEDIA_TYPE,
                    previous.map(|value| {
                        (
                            &value.jwks,
                            value.jwks_etag.as_ref(),
                            value.jwks_cache_seconds,
                        )
                    }),
                    state.profile.maximum_metadata_cache_seconds,
                    &fetch_policy,
                )
                .await?
            }
        };
        // Authorization-server metadata can legitimately require immediate
        // revalidation. That must not throw away a still-valid access token
        // when the revalidated token endpoint is byte-for-byte unchanged.
        // A changed endpoint gets a new provider before any credential is sent.
        let token_provider = if let Some(snapshot) = previous.filter(|snapshot| {
            snapshot.authorization.issuer == authorization.value.issuer
                && snapshot.authorization.token_endpoint == authorization.value.token_endpoint
        }) {
            Arc::clone(&snapshot.token_provider)
        } else {
            Arc::new(PrivateKeyJwt::new(
                PrivateKeyJwtConfig::new(
                    token_endpoint,
                    state.profile.client_id.clone(),
                    state.private_key.clone(),
                )
                .with_fetch_url_policy(fetch_policy),
            )?) as Arc<dyn TokenProvider>
        };
        let cache_seconds = protected
            .cache_seconds
            .min(authorization.cache_seconds)
            .min(jwks.cache_seconds);
        Ok(ProgressiveServiceSnapshot {
            protected: protected.value,
            authorization: authorization.value,
            jwks: jwks.value,
            token_provider,
            protected_etag: protected.etag,
            authorization_etag: authorization.etag,
            jwks_etag: jwks.etag,
            protected_cache_seconds: protected.cache_seconds,
            authorization_cache_seconds: authorization.cache_seconds,
            jwks_cache_seconds: jwks.cache_seconds,
            cache_seconds,
        })
    }

    async fn public_json<T: serde::de::DeserializeOwned + Clone>(
        &self,
        url: Url,
        media_type: &str,
        previous: Option<(&T, Option<&HeaderValue>, u64)>,
        maximum_cache_seconds: u64,
        fetch_policy: &FetchUrlPolicy,
    ) -> Result<PublicDocument<T>, EvidenceClientError> {
        let validated = fetch_policy
            .validate_dns_pinned_for_immediate_fetch_with_timeout(&url, self.config.connect_timeout)
            .await
            .map_err(|_| metadata_protocol_failure())?;
        let mut request = validated
            .immediate_get_with_timeout(self.config.request_timeout)
            .map_err(|_| metadata_protocol_failure())?
            .header(ACCEPT, media_type);
        if let Some(etag) = previous.and_then(|(_, etag, _)| etag) {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response = request
            .send()
            .await
            .map_err(|error| EvidenceClientError::transport(outbound::send_failure_kind(&error)))?;
        if validate_response_headers(response.headers()).is_err() {
            return Err(metadata_protocol_failure());
        }
        let response_etag = metadata_etag(response.headers())?;
        if response.status() == StatusCode::NOT_MODIFIED {
            let (value, requested_etag, previous_cache_seconds) =
                previous.ok_or_else(metadata_protocol_failure)?;
            let requested_etag = requested_etag.ok_or_else(metadata_protocol_failure)?;
            if response_etag
                .as_ref()
                .is_some_and(|etag| etag != requested_etag)
            {
                return Err(metadata_protocol_failure());
            }
            let cache_seconds = metadata_cache_seconds(
                response.headers(),
                maximum_cache_seconds,
                Some(previous_cache_seconds),
            )?;
            return Ok(PublicDocument {
                value: value.clone(),
                etag: response_etag.or_else(|| Some(requested_etag.clone())),
                cache_seconds,
            });
        }
        if !response.status().is_success()
            || response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !essence(value).eq_ignore_ascii_case(media_type))
        {
            return Err(metadata_protocol_failure());
        }
        let cache_seconds =
            metadata_cache_seconds(response.headers(), maximum_cache_seconds, None)?;
        let body = read_bounded(response, self.config.max_metadata_bytes)
            .await
            .map_err(|error| EvidenceClientError::transport(outbound::read_failure_kind(&error)))?;
        let value = serde_json::from_slice(&body).map_err(|_| metadata_protocol_failure())?;
        Ok(PublicDocument {
            value,
            etag: response_etag,
            cache_seconds,
        })
    }

    /// Validate and connect, without deciding the verification stance.
    fn build(config: EvidenceClientConfig) -> Result<Self, EvidenceClientError> {
        config.validate()?;
        let http = build_client(&config)?;
        Ok(Self {
            config,
            http,
            progressive: None,
        })
    }

    #[must_use]
    pub fn config(&self) -> &EvidenceClientConfig {
        &self.config
    }

    /// Close the expectations for one request and generate its nonce.
    ///
    /// No I/O happens here. The returned request is good for exactly one
    /// exchange.
    pub fn prepare(
        &self,
        spec: EvidenceRequestSpec,
    ) -> Result<PreparedEvidenceRequest, EvidenceClientError> {
        PreparedEvidenceRequest::new_with_revoked_key_ids(spec, self.config.revoked_key_ids.clone())
    }

    /// Close one independent policy and generate one independent nonce for
    /// every ordered item in a request batch.
    ///
    /// No I/O happens here. The returned batch is good for exactly one
    /// exchange and is deliberately not cloneable.
    pub fn prepare_batch(
        &self,
        spec: EvidenceRequestBatchSpec,
    ) -> Result<PreparedEvidenceRequestBatch, EvidenceClientError> {
        PreparedEvidenceRequestBatch::new_with_revoked_key_ids(
            spec,
            self.config.revoked_key_ids.clone(),
        )
    }

    /// Close the expectations for one holder-bound request and generate its
    /// nonce.
    ///
    /// No I/O happens here, and the returned request is good for exactly one
    /// exchange, exactly as [`EvidenceClient::prepare`] is. What it does not
    /// close is a verification policy: see [`PreparedHolderBoundRequest`] for
    /// why a holder-bound credential is not verified by the party that requests
    /// it.
    pub fn prepare_holder_bound(
        &self,
        spec: HolderBoundRequestSpec,
    ) -> Result<PreparedHolderBoundRequest, EvidenceClientError> {
        PreparedHolderBoundRequest::new(spec)
    }

    /// Close a self-contained offline verification context before a response
    /// exists.
    ///
    /// The retained context includes the client's pinned keys and the prepared
    /// policy, but no request selector values. Creating it performs no I/O.
    #[must_use]
    pub fn retain_verification(
        &self,
        prepared: &PreparedEvidenceRequest,
    ) -> RetainedEvidenceVerification {
        RetainedEvidenceVerification::new(prepared, self.config.trusted_jwks.clone())
    }

    /// Read the request shapes this requester is entitled to send.
    ///
    /// Discovery is authoring input, not a trust anchor. It tells a relying
    /// party what it may ask for; it never supplies verification expectations
    /// for a request already in flight.
    pub async fn discover(&self) -> Result<EvidenceDefinitionsDocument, EvidenceClientError> {
        let (document, trace_id): (EvidenceDefinitionsDocument, _) = self
            .get_json(DEFINITIONS_PATH, JSON_MEDIA_TYPE, Credential::Required)
            .await?;
        // These types would accept a later document that happened to fit them, and
        // the relying party would then author requests for a shape whose meaning
        // it guessed. The rest of the definitions contract is the deployment's to
        // apply; only the version this client reads is checked here.
        if document.schema != EVIDENCE_DEFINITIONS_SCHEMA_V1 {
            return Err(EvidenceClientError::Protocol {
                status: StatusCode::OK.as_u16(),
                code: None,
                trace_id,
                retry_after_seconds: None,
            });
        }
        Ok(document)
    }

    /// Read the deployment's published verification key set.
    ///
    /// This is for an out-of-band pinning workflow: fetch once, review the keys
    /// against what the deployment operator published elsewhere, and configure
    /// the reviewed set as the client's trusted key set. Verification never
    /// calls this. A key set fetched from the same origin as the response it
    /// would verify establishes nothing.
    pub async fn fetch_jwks(&self) -> Result<JwksDocument, EvidenceClientError> {
        // The published key set is public, and it is not a trust anchor here, so
        // there is nothing to gain by presenting the relying party's credential
        // to fetch it.
        let (document, _trace_id) = self
            .get_json(JWKS_PATH, JWKS_MEDIA_TYPE, Credential::None)
            .await?;
        Ok(document)
    }

    /// Send one prepared request and read the signed response.
    ///
    /// There is no retry, at this layer or below it. A nonce identifies exactly
    /// one request, and a policy accepts exactly the answer to that request, so
    /// a second attempt has to be a second [`EvidenceClient::prepare`] with a
    /// fresh nonce. Retrying the same bytes would let a stale answer satisfy a
    /// policy that was closed for a different exchange.
    ///
    /// This is enforced, not merely advised: `prepared` allows exactly one send,
    /// and a second call with the same prepared request returns a configuration
    /// failure without reaching the deployment. The deployment never
    /// uniqueness-checks a nonce, so a resend would earn a second source access
    /// and a second audit entry there for one relying-party decision.
    pub async fn send(
        &self,
        prepared: &PreparedEvidenceRequest,
    ) -> Result<RawEvidenceResponse, EvidenceClientError> {
        prepared.claim_single_send()?;
        self.post_evidence(prepared.response_format(), prepared.request_json()?)
            .await
    }

    /// Send one holder-bound request and read the credential response.
    ///
    /// This is [`EvidenceClient::send`] for a holder-bound request, with the
    /// same single-send rule and the same absence of retry, and it stops in the
    /// same place: the bytes are read, never judged. There is no
    /// `request_and_verify` counterpart, because the requester is not the party
    /// that verifies a holder-bound credential.
    pub async fn send_holder_bound(
        &self,
        prepared: &PreparedHolderBoundRequest,
    ) -> Result<RawEvidenceResponse, EvidenceClientError> {
        prepared.claim_single_send()?;
        self.post_evidence(prepared.response_format(), prepared.request_json()?)
            .await
    }

    /// Send one holder-bound batch request and read the issuance envelope.
    ///
    /// The batch rule is the holder-bound response format's: a request that did
    /// not ask for a batch is refused here rather than sent, because the
    /// `Accept` header was decided when the request was prepared.
    pub async fn send_holder_bound_batch(
        &self,
        prepared: &PreparedHolderBoundRequest,
    ) -> Result<SdJwtVcBatchResponse, EvidenceClientError> {
        if prepared.response_format() != EvidenceResponseFormat::SdJwtVcBatch {
            return Err(EvidenceClientError::configuration(
                "this prepared request did not ask for a batch response format",
            ));
        }
        let response = self.send_holder_bound(prepared).await?;
        SdJwtVcBatchResponse::parse(response.body())
    }

    /// POST one already-serialized request body and read the response under the
    /// bound its format carries.
    async fn post_evidence(
        &self,
        format: EvidenceResponseFormat,
        body: Vec<u8>,
    ) -> Result<RawEvidenceResponse, EvidenceClientError> {
        let url = self.endpoint(EVIDENCE_PATH)?;
        let response_media_type = format.media_type();
        let request = self
            .http
            .request(Method::POST, url)
            .header(ACCEPT, response_media_type)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .body(body);
        let response = self.exchange(request, Credential::Required).await?;
        self.expect_success(response, response_media_type, self.response_bound(format))
            .await
    }

    /// The byte bound one response in this format is read under.
    ///
    /// A batch answers with several credentials at once, so the contract bounds
    /// it explicitly. The relying party's own configured bound still applies,
    /// and whichever is smaller decides: neither party's limit is widened by
    /// the other's.
    fn response_bound(&self, format: EvidenceResponseFormat) -> u64 {
        match format {
            EvidenceResponseFormat::SignedJws | EvidenceResponseFormat::SdJwtVc => {
                self.config.max_response_bytes
            }
            EvidenceResponseFormat::SdJwtVcBatch => self
                .config
                .max_response_bytes
                .min(MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES as u64),
        }
    }

    /// Send one ordered multi-subject request batch and read its response
    /// envelope without trusting any member.
    ///
    /// The single-send claim is taken before serialization or I/O. There is no
    /// retry, and a second call with the same prepared batch fails locally.
    pub async fn send_batch(
        &self,
        prepared: &PreparedEvidenceRequestBatch,
    ) -> Result<RawEvidenceRequestBatchResponse, EvidenceClientError> {
        prepared.claim_single_send()?;
        let url = self.endpoint(EVIDENCE_BATCH_PATH)?;
        let request = self
            .http
            .request(Method::POST, url)
            .header(ACCEPT, EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .body(prepared.request_json()?);
        let response = self.exchange(request, Credential::Required).await?;
        let response = self
            .expect_success(
                response,
                EVIDENCE_REQUEST_BATCH_MEDIA_TYPE,
                self.config
                    .max_response_bytes
                    .min(MAX_EVIDENCE_REQUEST_BATCH_RESPONSE_BYTES as u64),
            )
            .await?;
        Ok(RawEvidenceRequestBatchResponse {
            body: response.body,
            trace_id: response.trace_id,
        })
    }

    /// Verify every available response member against the policy at the same
    /// position, or refuse the whole envelope.
    pub fn verify_batch(
        &self,
        prepared: &PreparedEvidenceRequestBatch,
        response: &RawEvidenceRequestBatchResponse,
    ) -> Result<VerifiedEvidenceRequestBatch, EvidenceClientError> {
        self.verify_batch_as_of(prepared, response, Utc::now())
    }

    /// Verify a request-batch envelope at a caller-selected instant.
    ///
    /// Parsing, exact item count, and all available signatures and policies
    /// must pass before any verified batch is returned. Available member `i`
    /// is checked only against policy `i`, whose independently generated nonce
    /// makes a swapped member fail rather than change positions silently.
    pub fn verify_batch_as_of(
        &self,
        prepared: &PreparedEvidenceRequestBatch,
        response: &RawEvidenceRequestBatchResponse,
        now: DateTime<Utc>,
    ) -> Result<VerifiedEvidenceRequestBatch, EvidenceClientError> {
        let envelope: EvidenceRequestBatchResponse = serde_json::from_slice(&response.body)
            .map_err(|_| batch_protocol_failure(response.trace_id.clone()))?;
        if envelope.schema != EVIDENCE_REQUEST_BATCH_SCHEMA_V1
            || envelope.items.len() != prepared.items().len()
        {
            return Err(batch_protocol_failure(response.trace_id.clone()));
        }

        let mut verified = Vec::with_capacity(envelope.items.len());
        for (prepared_item, response_item) in prepared.items().iter().zip(envelope.items) {
            match response_item {
                EvidenceRequestBatchResponseItem::Evidence { evidence } => {
                    let body = serde_json::to_vec(&evidence)
                        .map_err(|_| batch_protocol_failure(response.trace_id.clone()))?;
                    let raw = RawEvidenceResponse {
                        body,
                        trace_id: response.trace_id.clone(),
                    };
                    verified.push(VerifiedEvidenceRequestBatchItem::Available(
                        self.verify_as_of(prepared_item, &raw, now)?,
                    ));
                }
                EvidenceRequestBatchResponseItem::EvidenceNotAvailable => {
                    verified.push(VerifiedEvidenceRequestBatchItem::NotAvailable);
                }
            }
        }

        Ok(VerifiedEvidenceRequestBatch {
            items: verified,
            trace_id: response.trace_id.clone(),
        })
    }

    /// Send and atomically verify one prepared request batch.
    pub async fn request_and_verify_batch(
        &self,
        prepared: &PreparedEvidenceRequestBatch,
    ) -> Result<VerifiedEvidenceRequestBatch, EvidenceClientError> {
        let response = self.send_batch(prepared).await?;
        self.verify_batch(prepared, &response)
    }

    /// Verify a signed response against the policy its request closed.
    ///
    /// The trusted key set is the one pinned at construction, always.
    ///
    /// Unlike sending, verifying is unrestricted. It is offline, idempotent, and
    /// reaches no deployment, so a relying party may re-verify a retained
    /// response against its retained prepared request as often as it likes,
    /// including after the single send has been spent.
    pub fn verify(
        &self,
        prepared: &PreparedEvidenceRequest,
        response: &RawEvidenceResponse,
    ) -> Result<VerifiedEvidence, EvidenceClientError> {
        self.verify_as_of(prepared, response, Utc::now())
    }

    /// Request evidence and verify it, in one step.
    ///
    /// This spends the single send `prepared` allows, exactly as
    /// [`EvidenceClient::send`] does, so calling it twice with one prepared
    /// request fails locally on the second call.
    pub async fn request_and_verify(
        &self,
        prepared: &PreparedEvidenceRequest,
    ) -> Result<VerifiedEvidence, EvidenceClientError> {
        let response = self.send(prepared).await?;
        self.verify(prepared, &response)
    }

    /// Verify a retained response as of an explicit instant.
    ///
    /// [`EvidenceClient::verify`] judges a response against the current clock,
    /// which is right when the response has just arrived. This variant lets the
    /// relying party name the instant instead, and the two cases that need it are
    /// both about a response the relying party already holds:
    ///
    /// - Re-verifying a retained response when the decision is actually made,
    ///   rather than when the bytes arrived. The assertion's own validity
    ///   interval, plus the request's stated clock skew, then decides whether it
    ///   still answers the question.
    /// - Replaying a retained transaction record: the same bytes, the same
    ///   retained prepared request, and the instant the original decision was
    ///   taken, so an audit reaches the same verdict the relying party did.
    ///
    /// The instant only moves the clock. Every other expectation is the one the
    /// request closed, and the trusted key set is the one pinned at
    /// construction. Passing a future instant does not extend an assertion's
    /// validity; it only asks whether the assertion would have been acceptable
    /// then.
    ///
    /// A past instant is the direction that costs something. Naming the instant
    /// the bytes arrived, or any other stale instant, accepts an assertion whose
    /// validity interval has since elapsed: the question asked is whether it was
    /// acceptable then, and the answer stays yes forever. A caller deciding
    /// something now calls [`EvidenceClient::verify`], which judges the response
    /// against the current clock. This variant is for re-verifying a response
    /// already held, at an instant the caller can justify.
    ///
    /// The parameter is a [`chrono::DateTime<Utc>`], the same instant type the
    /// portable verifier's own policy takes.
    pub fn verify_as_of(
        &self,
        prepared: &PreparedEvidenceRequest,
        response: &RawEvidenceResponse,
        now: DateTime<Utc>,
    ) -> Result<VerifiedEvidence, EvidenceClientError> {
        self.retain_verification(prepared).verify_with_revocations(
            &response.body,
            now,
            Some(&self.config.revoked_key_ids),
            response.trace_id.clone(),
        )
    }

    /// Read one JSON document from a GET endpoint under the base URL.
    ///
    /// The two documents this serves, discovery and the published key set, are
    /// both authoring input rather than verification input, and a body that does
    /// not parse is a protocol failure rather than a refusal: the deployment
    /// answered, and the answer was not the document it promised.
    /// The response trace identifier is returned beside the document, so a
    /// caller that refuses the parsed document still has the one value the
    /// problem contract calls safe for support correlation.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        media_type: &str,
        credential: Credential,
    ) -> Result<(T, Option<String>), EvidenceClientError> {
        let url = self.endpoint(path)?;
        let request = self
            .http
            .request(Method::GET, url)
            .header(ACCEPT, media_type);
        let response = self.exchange(request, credential).await?;
        let body = self
            .expect_success(response, media_type, self.config.max_metadata_bytes)
            .await?;
        let document =
            serde_json::from_slice(&body.body).map_err(|_| EvidenceClientError::Protocol {
                status: StatusCode::OK.as_u16(),
                code: None,
                trace_id: body.trace_id.clone(),
                retry_after_seconds: None,
            })?;
        Ok((document, body.trace_id))
    }

    /// Resolve one endpoint under the configured base URL.
    fn endpoint(&self, path: &str) -> Result<Url, EvidenceClientError> {
        // `join` on a base whose path lacks a trailing separator would discard
        // the last segment, so the deployment prefix is preserved explicitly.
        let mut url = self.config.base_url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|()| {
                EvidenceClientError::configuration("the base URL must accept path segments")
            })?;
            segments.pop_if_empty();
            for segment in path.split('/') {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    /// Attach the credential when the endpoint requires one, and perform the
    /// exchange.
    async fn exchange(
        &self,
        request: reqwest::RequestBuilder,
        credential: Credential,
    ) -> Result<reqwest::Response, EvidenceClientError> {
        let request = match credential {
            Credential::Required => {
                let token = self.config.token_provider.bearer_token().await?;
                request.header(AUTHORIZATION, token.authorization_header_value())
            }
            Credential::None => request,
        };
        request
            .send()
            .await
            .map_err(|error| EvidenceClientError::transport(outbound::send_failure_kind(&error)))
    }

    /// Read a successful response of exactly one media type, or map the
    /// deployment's answer onto a client failure.
    ///
    /// `max_bytes` is the caller's, because the signed response and the
    /// deployment's metadata documents are bounded by separate configuration
    /// decisions.
    async fn expect_success(
        &self,
        response: reqwest::Response,
        expected_media_type: &str,
        max_bytes: u64,
    ) -> Result<RawEvidenceResponse, EvidenceClientError> {
        let status = response.status().as_u16();
        if validate_response_headers(response.headers()).is_err() {
            return Err(EvidenceClientError::Protocol {
                status,
                code: None,
                trace_id: None,
                retry_after_seconds: None,
            });
        }
        let trace_id = response_trace_id(response.headers());
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let retry_after_seconds =
            retry_after_seconds(response.headers(), MAXIMUM_RETRY_AFTER_SECONDS);

        if trace_id.is_none() {
            return Err(EvidenceClientError::Protocol {
                status,
                code: None,
                trace_id: None,
                retry_after_seconds: None,
            });
        }

        let body = match read_bounded(response, max_bytes).await {
            Ok(body) => body,
            // The status and the correlation identifier arrived before the body
            // did. A refusal keeps them, because they are the whole support
            // workflow this crate offers and the unread body would have carried
            // nothing else the caller may act on.
            Err(_) if !(200..300).contains(&status) => {
                return Err(EvidenceClientError::Protocol {
                    status,
                    code: None,
                    trace_id,
                    retry_after_seconds: None,
                })
            }
            // An answer meant as a success has no status or code worth
            // reporting, only the reason its bytes never arrived.
            Err(error) => {
                return Err(EvidenceClientError::transport(outbound::read_failure_kind(
                    &error,
                )))
            }
        };

        if !(200..300).contains(&status) {
            return Err(map_problem(
                status,
                media_type.as_deref(),
                &body,
                retry_after_seconds,
                trace_id.as_deref(),
            ));
        }
        if status != StatusCode::OK.as_u16()
            || !media_type
                .as_deref()
                .is_some_and(|value| essence(value).eq_ignore_ascii_case(expected_media_type))
        {
            return Err(EvidenceClientError::Protocol {
                status,
                code: None,
                trace_id,
                retry_after_seconds: None,
            });
        }
        Ok(RawEvidenceResponse { body, trace_id })
    }
}

/// A relying party that requests holder-bound credentials and does not verify
/// them.
///
/// The case this exists for is a credential delivery front end: it asks the
/// deployment for a holder-bound credential and hands the bytes to a wallet.
/// The wallet, or whoever the wallet later presents to, is the verifier. That
/// verification needs a key-binding JWT the holder has not created at issuance,
/// so the requester could not perform it even if it wanted to.
///
/// This type carries no verification method at all. Not a method that returns
/// an error, and not a method guarded by a flag: the path is absent, so a
/// non-verifying client cannot be mistaken for one that checked something. It
/// also carries no audience-scoped request path, because an audience-scoped
/// answer is addressed to the requester itself and there is no one else to
/// verify it.
///
/// The audience-scoped path is untouched by this type's existence.
/// [`EvidenceClient`] still requires a pinned key set, still verifies, and is
/// unreachable from a configuration that declined to verify.
#[derive(Debug)]
pub struct NonVerifyingEvidenceClient {
    inner: EvidenceClient,
}

impl NonVerifyingEvidenceClient {
    /// Build a non-verifying client for one deployment.
    ///
    /// The configuration must be one built by
    /// [`EvidenceClientConfig::without_verification`]. A configuration that
    /// pinned a key set is refused, so declining to verify is always a stated
    /// decision rather than a side effect of which constructor was reached for.
    pub fn new(config: EvidenceClientConfig) -> Result<Self, EvidenceClientError> {
        if config.verifies() {
            return Err(EvidenceClientError::configuration(
                "this client does not verify, so its configuration must decline verification",
            ));
        }
        Ok(Self {
            inner: EvidenceClient::build(config)?,
        })
    }

    #[must_use]
    pub fn config(&self) -> &EvidenceClientConfig {
        self.inner.config()
    }

    /// Close the expectations for one holder-bound request and generate its
    /// nonce. See [`EvidenceClient::prepare_holder_bound`].
    pub fn prepare_holder_bound(
        &self,
        spec: HolderBoundRequestSpec,
    ) -> Result<PreparedHolderBoundRequest, EvidenceClientError> {
        self.inner.prepare_holder_bound(spec)
    }

    /// Send one holder-bound request and read the credential response. See
    /// [`EvidenceClient::send_holder_bound`].
    pub async fn send_holder_bound(
        &self,
        prepared: &PreparedHolderBoundRequest,
    ) -> Result<RawEvidenceResponse, EvidenceClientError> {
        self.inner.send_holder_bound(prepared).await
    }

    /// Send one holder-bound batch request and read the issuance envelope. See
    /// [`EvidenceClient::send_holder_bound_batch`].
    pub async fn send_holder_bound_batch(
        &self,
        prepared: &PreparedHolderBoundRequest,
    ) -> Result<SdJwtVcBatchResponse, EvidenceClientError> {
        self.inner.send_holder_bound_batch(prepared).await
    }

    /// Read the request shapes this requester is entitled to send. See
    /// [`EvidenceClient::discover`].
    pub async fn discover(&self) -> Result<EvidenceDefinitionsDocument, EvidenceClientError> {
        self.inner.discover().await
    }

    /// Read the deployment's published verification key set, for an out-of-band
    /// pinning workflow. See [`EvidenceClient::fetch_jwks`].
    ///
    /// This is not verification, and it is not a way back to it: the document is
    /// returned to the caller and this client never consults it.
    pub async fn fetch_jwks(&self) -> Result<JwksDocument, EvidenceClientError> {
        self.inner.fetch_jwks().await
    }
}

fn batch_protocol_failure(trace_id: Option<String>) -> EvidenceClientError {
    EvidenceClientError::Protocol {
        status: StatusCode::OK.as_u16(),
        code: None,
        trace_id,
        retry_after_seconds: None,
    }
}

fn metadata_protocol_failure() -> EvidenceClientError {
    EvidenceClientError::Protocol {
        status: StatusCode::OK.as_u16(),
        code: None,
        trace_id: None,
        retry_after_seconds: None,
    }
}

fn cache_deadlines(
    now: Instant,
    cache_seconds: u64,
    maximum_cache_seconds: u64,
) -> (Instant, Instant) {
    let expires_at = now + Duration::from_secs(cache_seconds.min(maximum_cache_seconds));
    let stale_until = if cache_seconds == 0 {
        now
    } else {
        now + Duration::from_secs(maximum_cache_seconds)
    };
    (expires_at, stale_until)
}

fn metadata_etag(headers: &HeaderMap) -> Result<Option<HeaderValue>, EvidenceClientError> {
    let Some(value) = headers.get(ETAG) else {
        return Ok(None);
    };
    let encoded = value.to_str().map_err(|_| metadata_protocol_failure())?;
    if encoded.len() < 2
        || encoded.len() > 256
        || encoded.starts_with("W/")
        || !encoded.starts_with('"')
        || !encoded.ends_with('"')
        || encoded[1..encoded.len() - 1]
            .bytes()
            .any(|byte| byte <= 0x20 || byte == 0x7f || byte == b'"')
    {
        return Err(metadata_protocol_failure());
    }
    Ok(Some(value.clone()))
}

fn metadata_cache_seconds(
    headers: &HeaderMap,
    maximum_cache_seconds: u64,
    retained_on_absence: Option<u64>,
) -> Result<u64, EvidenceClientError> {
    let mut values = headers.get_all(CACHE_CONTROL).iter().peekable();
    if values.peek().is_none() {
        return Ok(retained_on_absence
            .unwrap_or(maximum_cache_seconds)
            .min(maximum_cache_seconds));
    }
    let mut maximum_age = None;
    for value in values {
        let value = value.to_str().map_err(|_| metadata_protocol_failure())?;
        for directive in value.split(',').map(str::trim) {
            if directive.eq_ignore_ascii_case("no-store")
                || directive.eq_ignore_ascii_case("no-cache")
                || directive.eq_ignore_ascii_case("private")
            {
                return Ok(0);
            }
            if let Some((name, seconds)) = directive.split_once('=') {
                if name.eq_ignore_ascii_case("max-age") {
                    let seconds = seconds
                        .parse::<u64>()
                        .map_err(|_| metadata_protocol_failure())?;
                    maximum_age =
                        Some(maximum_age.map_or(seconds, |current: u64| current.min(seconds)));
                }
            }
        }
    }
    Ok(maximum_age
        .unwrap_or(maximum_cache_seconds)
        .min(maximum_cache_seconds))
}

fn metadata_fetch_policy(trust: &TrustProfile) -> FetchUrlPolicy {
    match trust {
        TrustProfile::LocalLoopbackDiscovery => FetchUrlPolicy::dev(),
        TrustProfile::HttpsDiscovery | TrustProfile::PinnedJwks { .. } => FetchUrlPolicy::strict(),
    }
}

fn authorization_server_metadata_is_compatible(
    metadata: &AuthorizationServerMetadata,
    announced_issuer: &str,
) -> bool {
    metadata.issuer == announced_issuer
        && metadata
            .grant_types_supported
            .iter()
            .any(|value| value == "client_credentials")
        && metadata
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|value| value == "private_key_jwt")
}

fn validate_metadata_url(url: &Url, trust: &TrustProfile) -> Result<(), EvidenceClientError> {
    let exact_local_loopback = url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some_and(|port| port != 0);
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(metadata_protocol_failure());
    }
    let accepted = match trust {
        TrustProfile::LocalLoopbackDiscovery => exact_local_loopback,
        TrustProfile::HttpsDiscovery | TrustProfile::PinnedJwks { .. } => url.scheme() == "https",
    };
    if accepted {
        Ok(())
    } else {
        Err(metadata_protocol_failure())
    }
}

fn metadata_endpoint(issuer: &Url) -> Result<Url, EvidenceClientError> {
    if issuer.query().is_some() || issuer.fragment().is_some() {
        return Err(metadata_protocol_failure());
    }
    let issuer_path = issuer.path().trim_matches('/');
    let metadata_path = if issuer_path.is_empty() {
        "/.well-known/oauth-authorization-server".to_owned()
    } else {
        format!("/.well-known/oauth-authorization-server/{issuer_path}")
    };
    let mut metadata = issuer.clone();
    metadata.set_path(&metadata_path);
    metadata.set_query(None);
    metadata.set_fragment(None);
    Ok(metadata)
}

fn validate_profile_expectations(
    profile: &EvidenceClientProfile,
    definitions: &EvidenceDefinitionsDocument,
) -> Result<(), EvidenceClientError> {
    if profile
        .expected
        .audience
        .as_ref()
        .is_some_and(|value| value != &definitions.audience)
        || profile
            .expected
            .issuer
            .as_ref()
            .is_some_and(|value| value != &definitions.issued_by)
        || profile
            .expected
            .provider
            .as_ref()
            .is_some_and(|value| value != &definitions.provided_by)
    {
        return Err(EvidenceClientError::configuration(
            "the discovered service does not match the profile's expected identity",
        ));
    }
    Ok(())
}

/// Read exactly one strict response trace context. Multiple field lines are an
/// ambiguous provenance claim, so they are rejected rather than first-wins.
fn response_trace_id(headers: &HeaderMap) -> Option<String> {
    registry_platform_httpsec::response_trace_id(headers)
        .ok()
        .map(|trace_id| trace_id.as_str().to_owned())
}

/// Build the outbound client from the pinned deployment options.
fn build_client(config: &EvidenceClientConfig) -> Result<reqwest::Client, EvidenceClientError> {
    outbound::build_client(OutboundOptions {
        request_timeout: config.request_timeout,
        connect_timeout: config.connect_timeout,
        user_agent: config.user_agent.as_deref(),
        trusted_root_certificates: config
            .trusted_root_certificates
            .as_ref()
            .map(|pem| pem.as_slice()),
    })
    .map_err(EvidenceClientError::configuration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        batch::{EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE, SD_JWT_VC_BATCH_SCHEMA_V1},
        error::TransportKind,
        fixtures::{
            holder_key, signed_evidence, SignedEvidenceFixture, AUDIENCE, CONCEPT,
            CONFIGURATION_REVISION, EVIDENCE_TYPE, ISSUED_BY, MAXIMUM_LIFETIME_SECONDS,
            PROVIDED_BY, PURPOSE, REQUIREMENT,
        },
        outbound::read_failure_kind,
        prepare::{EvidenceRequestSpec, SubjectExpectations, SubjectRequest},
        request::SelectorValue,
        response_format::EvidenceResponseFormat,
        token::StaticToken,
    };
    use registry_evidence_verifier::{
        verifier::{
            ExpectedFormDocument, ExpectedOutputDocument, ExpectedScalarFormDocument,
            VerificationError,
        },
        AssuranceProfile, EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
    };
    use registry_platform_httputil::BoundedReadError;
    use std::{net::TcpListener, sync::Arc, time::Duration};
    use wiremock::{
        matchers::{any, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    /// A canonical lower-case W3C trace context for HTTP fixtures.
    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn config_for(base_url: &str, fixture: &SignedEvidenceFixture) -> EvidenceClientConfig {
        EvidenceClientConfig::new(
            Url::parse(base_url).expect("the base URL parses"),
            Arc::new(StaticToken::new("test-token").expect("the credential is accepted")),
            fixture.trusted_jwks.clone(),
            Vec::new(),
        )
    }

    fn client_for(base_url: &str, fixture: &SignedEvidenceFixture) -> EvidenceClient {
        EvidenceClient::new(config_for(base_url, fixture)).expect("the client is configured")
    }

    /// A loopback origin with nothing listening on it. The port is reserved and
    /// released, so the connection attempt is refused rather than answered.
    fn closed_loopback_origin() -> String {
        let reservation =
            TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port is available");
        let port = reservation
            .local_addr()
            .expect("the reservation has an address")
            .port();
        drop(reservation);
        format!("http://127.0.0.1:{port}")
    }

    fn client(fixture: &SignedEvidenceFixture) -> EvidenceClient {
        client_for("https://evidence.example.org/", fixture)
    }

    fn spec(subject_expectations: SubjectExpectations) -> EvidenceRequestSpec {
        EvidenceRequestSpec {
            response_format: EvidenceResponseFormat::SignedJws,
            requirement: REQUIREMENT.to_owned(),
            purpose: PURPOSE.to_owned(),
            audience: AUDIENCE.to_owned(),
            evidence_type: EVIDENCE_TYPE.to_owned(),
            issued_by: ISSUED_BY.to_owned(),
            provided_by: PROVIDED_BY.to_owned(),
            configuration_revision: CONFIGURATION_REVISION.to_owned(),
            expected_assurance_profile: AssuranceProfile::Local,
            subjects: vec![SubjectRequest {
                role: "subject".to_owned(),
                selector_profile: "record-lookup-v1".to_owned(),
                selector_values: Some(vec![(
                    "record_reference".to_owned(),
                    SelectorValue::from("synthetic-record-001"),
                )]),
            }],
            holder_keys: Vec::new(),
            expected_outputs: vec![ExpectedOutputDocument {
                handle: "status-holds".to_owned(),
                concept: CONCEPT.to_owned(),
                required: true,
                form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
            }],
            maximum_assertion_lifetime_seconds: MAXIMUM_LIFETIME_SECONDS,
            clock_skew_seconds: 60,
            subject_expectations,
        }
    }

    fn raw(body: Vec<u8>) -> RawEvidenceResponse {
        RawEvidenceResponse {
            body,
            trace_id: Some(TRACE_ID.to_owned()),
        }
    }

    fn request_batch_spec(item_count: usize) -> EvidenceRequestBatchSpec {
        let singular = spec(SubjectExpectations::AcceptFirstUse);
        EvidenceRequestBatchSpec {
            requirement: singular.requirement,
            purpose: singular.purpose,
            audience: singular.audience,
            evidence_type: singular.evidence_type,
            issued_by: singular.issued_by,
            provided_by: singular.provided_by,
            configuration_revision: singular.configuration_revision,
            expected_assurance_profile: singular.expected_assurance_profile,
            expected_outputs: singular.expected_outputs,
            maximum_assertion_lifetime_seconds: singular.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: singular.clock_skew_seconds,
            items: (0..item_count)
                .map(|_| crate::EvidenceRequestBatchItemSpec {
                    subjects: singular.subjects.clone(),
                    subject_expectations: SubjectExpectations::AcceptFirstUse,
                })
                .collect(),
        }
    }

    fn available_batch_item(jws: Vec<u8>) -> serde_json::Value {
        serde_json::json!({
            "result": "evidence",
            "evidence": serde_json::from_slice::<serde_json::Value>(&jws)
                .expect("the fixture creates a flattened JWS")
        })
    }

    fn request_batch_envelope(items: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": EVIDENCE_REQUEST_BATCH_SCHEMA_V1,
            "type": "EvidenceRequestBatchResponse",
            "items": items,
        }))
        .expect("the response envelope serializes")
    }

    fn raw_request_batch(items: Vec<serde_json::Value>) -> RawEvidenceRequestBatchResponse {
        RawEvidenceRequestBatchResponse {
            body: request_batch_envelope(items),
            trace_id: Some(TRACE_ID.to_owned()),
        }
    }

    #[test]
    fn a_response_traceparent_must_appear_exactly_once() {
        let mut headers = HeaderMap::new();
        headers.append(TRACEPARENT_HEADER, HeaderValue::from_static(TRACEPARENT));
        assert_eq!(response_trace_id(&headers), Some(TRACE_ID.to_owned()));
        headers.append(TRACEPARENT_HEADER, HeaderValue::from_static(TRACEPARENT));
        assert_eq!(response_trace_id(&headers), None);
    }

    #[test]
    fn every_endpoint_hangs_off_the_configured_base_url_including_its_prefix() {
        let fixture = signed_evidence();
        for (base, evidence, definitions, jwks) in [
            (
                "https://evidence.example.org",
                "https://evidence.example.org/v1/evidence",
                "https://evidence.example.org/v1/evidence-definitions",
                "https://evidence.example.org/.well-known/evidence/jwks.json",
            ),
            (
                "https://evidence.example.org/registry/",
                "https://evidence.example.org/registry/v1/evidence",
                "https://evidence.example.org/registry/v1/evidence-definitions",
                "https://evidence.example.org/registry/.well-known/evidence/jwks.json",
            ),
            (
                "https://evidence.example.org/registry",
                "https://evidence.example.org/registry/v1/evidence",
                "https://evidence.example.org/registry/v1/evidence-definitions",
                "https://evidence.example.org/registry/.well-known/evidence/jwks.json",
            ),
        ] {
            let client = client_for(base, &fixture);
            for (path, expected) in [
                (EVIDENCE_PATH, evidence),
                (DEFINITIONS_PATH, definitions),
                (JWKS_PATH, jwks),
            ] {
                assert_eq!(
                    client.endpoint(path).expect("the path resolves").as_str(),
                    expected
                );
            }
        }
    }

    #[test]
    fn a_pinned_subject_set_verifies_the_response_it_was_pinned_for() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::Pinned(vec![
                ExpectedSubjectDocument {
                    role: "subject".to_owned(),
                    binding: fixture.subject_binding.clone(),
                },
            ])))
            .expect("the specification is accepted");
        let response = raw(fixture.sign(prepared.request_nonce()));

        let verified = client
            .verify_as_of(&prepared, &response, fixture.now)
            .expect("the response verifies");
        assert_eq!(verified.trace_id(), Some(TRACE_ID));
        assert_eq!(
            verified.evidence().request_nonce,
            Some(prepared.request_nonce().to_owned())
        );
        assert_eq!(
            serde_json::to_value(verified.pinned_subject_expectations())
                .expect("the expectations serialize"),
            serde_json::json!([{"role": "subject", "binding": fixture.subject_binding}])
        );
    }

    /// The whole point of pinning: once the relying party holds the binding, a
    /// response about someone else is a verification failure, not an answer.
    #[test]
    fn a_pinned_subject_set_refuses_a_response_about_another_subject() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::Pinned(vec![
                ExpectedSubjectDocument {
                    role: "subject".to_owned(),
                    binding: fixture.subject_binding.clone(),
                },
            ])))
            .expect("the specification is accepted");
        let other_subject = "urn:evidence:subject:v1_WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo";
        let response =
            raw(fixture.sign_with_subject_binding(prepared.request_nonce(), other_subject));

        assert_eq!(
            client
                .verify_as_of(&prepared, &response, fixture.now)
                .expect_err("the response is refused"),
            EvidenceClientError::Verification(VerificationError::Policy)
        );
    }

    #[tokio::test]
    async fn an_unknown_response_key_never_triggers_metadata_refresh() {
        let server = MockServer::start().await;
        let trusted = signed_evidence();
        let untrusted = signed_evidence();
        let client = client_for(&server.uri(), &trusted);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the request policy closes");
        let response = raw(untrusted.sign(prepared.request_nonce()));

        assert!(matches!(
            client.verify_as_of(&prepared, &response, untrusted.now),
            Err(EvidenceClientError::Verification(VerificationError::Key))
        ));
        assert!(
            server
                .received_requests()
                .await
                .expect("the server records requests")
                .is_empty(),
            "an unknown response key must not fetch or refresh metadata"
        );
    }

    #[test]
    fn first_use_acceptance_adopts_the_subject_set_and_exposes_it_for_pinning() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");
        let response = raw(fixture.sign(prepared.request_nonce()));

        let verified = client
            .verify_as_of(&prepared, &response, fixture.now)
            .expect("the response verifies");
        let pinned = verified.pinned_subject_expectations();
        assert_eq!(pinned.len(), 1);
        assert_eq!(pinned[0].binding, fixture.subject_binding);

        // The adopted bindings are exactly what a later pinned request needs.
        let next = client
            .prepare(spec(SubjectExpectations::Pinned(pinned)))
            .expect("the specification is accepted");
        let next_response = raw(fixture.sign(next.request_nonce()));
        assert!(client
            .verify_as_of(&next, &next_response, fixture.now)
            .is_ok());
    }

    /// A retained response is judged again at the instant the decision is made,
    /// against the same closed policy. The assertion's own validity interval is
    /// what decides whether it still answers the question.
    #[test]
    fn a_retained_response_is_verifiable_at_a_chosen_decision_instant() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");
        let response = raw(fixture.sign(prepared.request_nonce()));
        let seconds = |count: i64| {
            fixture.now + chrono::TimeDelta::try_seconds(count).expect("the offset is valid")
        };
        let lifetime = i64::try_from(MAXIMUM_LIFETIME_SECONDS).expect("the lifetime fits");

        client
            .verify_as_of(&prepared, &response, seconds(lifetime / 2))
            .expect("the assertion is still within its validity interval");
        assert_eq!(
            client
                .verify_as_of(&prepared, &response, seconds(lifetime * 2))
                .expect_err("the assertion has expired"),
            EvidenceClientError::Verification(VerificationError::Time)
        );
    }

    /// First-use acceptance defers the subject question and nothing else.
    #[test]
    fn first_use_acceptance_still_enforces_every_other_expectation() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");

        // An answer to a different request, so a different nonce.
        let other = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");
        assert_eq!(
            client
                .verify_as_of(
                    &prepared,
                    &raw(fixture.sign(other.request_nonce())),
                    fixture.now
                )
                .expect_err("the response is refused"),
            EvidenceClientError::Verification(VerificationError::Policy)
        );

        // An answer signed by a key the relying party did not pin.
        let untrusted = signed_evidence();
        assert_eq!(
            client
                .verify_as_of(
                    &prepared,
                    &raw(untrusted.sign(prepared.request_nonce())),
                    fixture.now
                )
                .expect_err("the response is refused"),
            EvidenceClientError::Verification(VerificationError::Key)
        );

        // An answer whose stated purpose is not the one asked for.
        assert_eq!(
            client
                .verify_as_of(
                    &prepared,
                    &raw(fixture.sign_with_purpose(prepared.request_nonce(), "other-decision")),
                    fixture.now
                )
                .expect_err("the response is refused"),
            EvidenceClientError::Verification(VerificationError::Policy)
        );

        // An answer outside its own validity interval.
        assert_eq!(
            client
                .verify_as_of(
                    &prepared,
                    &raw(fixture.sign(prepared.request_nonce())),
                    fixture.now + chrono::TimeDelta::try_days(2).expect("the offset is valid")
                )
                .expect_err("the response is refused"),
            EvidenceClientError::Verification(VerificationError::Time)
        );
    }

    #[test]
    fn a_revoked_identifier_overrides_the_still_pinned_key() {
        let fixture = signed_evidence();
        let key_id = fixture.trusted_jwks.keys[0]["kid"]
            .as_str()
            .expect("the fixture key has an identifier")
            .to_owned();
        let client = EvidenceClient::new(EvidenceClientConfig::new(
            Url::parse("https://evidence.example.org").expect("the base URL parses"),
            Arc::new(StaticToken::new("test-token").expect("the credential is accepted")),
            fixture.trusted_jwks.clone(),
            vec![key_id.clone()],
        ))
        .expect("the denylisted cached key is valid configuration");
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the request is prepared");
        assert_eq!(prepared.policy_document().revoked_key_ids, [key_id]);
        let response = raw(fixture.sign(prepared.request_nonce()));
        assert_eq!(
            client
                .verify_as_of(&prepared, &response, fixture.now)
                .expect_err("the revoked key is refused before cached selection"),
            EvidenceClientError::Verification(VerificationError::Key)
        );
    }

    /// First-use acceptance defers which subject an assertion is about. It does
    /// not defer which roles were asked about, so a response that renames a role,
    /// adds one, or drops one is refused rather than adopted.
    #[test]
    fn first_use_acceptance_adopts_only_the_roles_the_request_asked_about() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let other = "urn:evidence:subject:v1_WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo";
        for (subjects, expected) in [
            // A role the request never named.
            (
                serde_json::json!([{"role": "other-role", "binding": fixture.subject_binding}]),
                VerificationError::Policy,
            ),
            // The requested role plus one the request never named.
            (
                serde_json::json!([
                    {"role": "subject", "binding": fixture.subject_binding},
                    {"role": "other-role", "binding": other},
                ]),
                VerificationError::Policy,
            ),
            // The requested role twice.
            (
                serde_json::json!([
                    {"role": "subject", "binding": fixture.subject_binding},
                    {"role": "subject", "binding": other},
                ]),
                VerificationError::Policy,
            ),
            // No subject at all. The payload contract requires one, so the
            // verifier refuses this before any policy comparison.
            (serde_json::json!([]), VerificationError::Payload),
        ] {
            let prepared = client
                .prepare(spec(SubjectExpectations::AcceptFirstUse))
                .expect("the specification is accepted");
            let response = raw(fixture.sign_with_subjects(prepared.request_nonce(), subjects));
            assert_eq!(
                client
                    .verify_as_of(&prepared, &response, fixture.now)
                    .expect_err("the response is refused"),
                EvidenceClientError::Verification(expected)
            );
        }
    }

    /// Under first-use acceptance an unreadable response yields no adopted
    /// subject, so the verifier refuses it instead of the client guessing.
    #[test]
    fn first_use_acceptance_refuses_a_response_it_cannot_read() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");

        for body in [
            b"not json".to_vec(),
            br#"{"protected":"","payload":"","signature":""}"#.to_vec(),
            br#"{"protected":"AA","payload":"!!!","signature":"AA"}"#.to_vec(),
        ] {
            assert!(client
                .verify_as_of(&prepared, &raw(body), fixture.now)
                .is_err());
        }
    }

    /// A prepared request is a single-use capability. The second send is refused
    /// locally, so a deployment never sees one nonce twice and never repeats the
    /// source access and audit entries a single request earns.
    #[tokio::test]
    async fn a_prepared_request_reaches_the_deployment_at_most_once() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = client_for(&server.uri(), &fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(
                        fixture.sign(prepared.request_nonce()),
                        EVIDENCE_JWS_MEDIA_TYPE,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        client
            .send(&prepared)
            .await
            .expect("the first send happens");
        assert_eq!(
            client
                .send(&prepared)
                .await
                .expect_err("the second send is refused"),
            EvidenceClientError::configuration(
                "a prepared request may be sent once; prepare again for a fresh nonce"
            )
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("the stub records what it received")
                .len(),
            1,
            "the refused send must not reach the deployment"
        );
    }

    #[tokio::test]
    async fn a_prepared_request_batch_has_the_exact_exchange_and_reaches_it_once() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = client_for(&server.uri(), &fixture);
        let prepared = client
            .prepare_batch(request_batch_spec(2))
            .expect("the request batch is prepared");
        let expected_body: serde_json::Value = serde_json::from_slice(
            &prepared
                .request_json()
                .expect("the request batch serializes"),
        )
        .expect("the request batch is JSON");
        Mock::given(method("POST"))
            .and(path("/v1/evidence/batch"))
            .and(header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE))
            .and(header("content-type", JSON_MEDIA_TYPE))
            .and(wiremock::matchers::body_json(expected_body))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(
                        request_batch_envelope(vec![
                            serde_json::json!({"result": "evidence_not_available"}),
                            serde_json::json!({"result": "evidence_not_available"}),
                        ]),
                        EVIDENCE_REQUEST_BATCH_MEDIA_TYPE,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        client
            .send_batch(&prepared)
            .await
            .expect("the first send reaches the batch endpoint");
        assert_eq!(
            client
                .send_batch(&prepared)
                .await
                .expect_err("the second send is refused locally"),
            EvidenceClientError::configuration(
                "a prepared request batch may be sent once; prepare again for fresh nonces"
            )
        );
    }

    #[tokio::test]
    async fn request_and_verify_batch_composes_one_exchange_and_atomic_verification() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = client_for(&server.uri(), &fixture);
        let prepared = client
            .prepare_batch(request_batch_spec(1))
            .expect("the request batch is prepared");
        Mock::given(method("POST"))
            .and(path("/v1/evidence/batch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(
                        request_batch_envelope(vec![
                            serde_json::json!({"result": "evidence_not_available"}),
                        ]),
                        EVIDENCE_REQUEST_BATCH_MEDIA_TYPE,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let verified = client
            .request_and_verify_batch(&prepared)
            .await
            .expect("the unavailable positional result is a verified batch outcome");
        assert!(matches!(
            verified.item(0),
            Some(VerifiedEvidenceRequestBatchItem::NotAvailable)
        ));
    }

    #[test]
    fn request_batch_verification_accepts_mixed_ordered_results() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare_batch(request_batch_spec(2))
            .expect("the request batch is prepared");
        let response = raw_request_batch(vec![
            available_batch_item(fixture.sign(prepared.request_nonce(0).expect("the first nonce"))),
            serde_json::json!({"result": "evidence_not_available"}),
        ]);

        let verified = client
            .verify_batch_as_of(&prepared, &response, fixture.now)
            .expect("every available member verifies");
        assert_eq!(verified.count(), 2);
        let Some(VerifiedEvidenceRequestBatchItem::Available(first)) = verified.item(0) else {
            panic!("the first item should be available")
        };
        assert_eq!(
            first.evidence().request_nonce.as_deref(),
            prepared.request_nonce(0)
        );
        assert!(matches!(
            verified.item(1),
            Some(VerifiedEvidenceRequestBatchItem::NotAvailable)
        ));
        assert_eq!(verified.trace_id(), Some(TRACE_ID));
    }

    #[test]
    fn request_batch_verification_refuses_swapped_nonces() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare_batch(request_batch_spec(2))
            .expect("the request batch is prepared");
        let response = raw_request_batch(vec![
            available_batch_item(
                fixture.sign(prepared.request_nonce(1).expect("the second nonce")),
            ),
            available_batch_item(fixture.sign(prepared.request_nonce(0).expect("the first nonce"))),
        ]);

        assert_eq!(
            client
                .verify_batch_as_of(&prepared, &response, fixture.now)
                .expect_err("a member cannot move to another policy position"),
            EvidenceClientError::Verification(VerificationError::Policy)
        );
    }

    #[test]
    fn request_batch_verification_is_atomic_when_one_signature_is_bad() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare_batch(request_batch_spec(2))
            .expect("the request batch is prepared");
        let first =
            available_batch_item(fixture.sign(prepared.request_nonce(0).expect("the first nonce")));
        let mut second = available_batch_item(
            fixture.sign(prepared.request_nonce(1).expect("the second nonce")),
        );
        second["evidence"]["signature"] = serde_json::Value::String("AA".to_owned());

        let failure = client
            .verify_batch_as_of(
                &prepared,
                &raw_request_batch(vec![first, second]),
                fixture.now,
            )
            .expect_err("one bad available member refuses the whole batch");
        assert!(matches!(failure, EvidenceClientError::Verification(_)));
    }

    #[test]
    fn request_batch_verification_refuses_malformed_missing_and_extra_members() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare_batch(request_batch_spec(2))
            .expect("the request batch is prepared");
        let unavailable = || serde_json::json!({"result": "evidence_not_available"});
        let responses = [
            RawEvidenceRequestBatchResponse {
                body: b"not json".to_vec(),
                trace_id: Some(TRACE_ID.to_owned()),
            },
            raw_request_batch(vec![unavailable()]),
            raw_request_batch(vec![unavailable(), unavailable(), unavailable()]),
            RawEvidenceRequestBatchResponse {
                body: serde_json::to_vec(&serde_json::json!({
                    "schema": "registry.other/v1",
                    "type": "EvidenceRequestBatchResponse",
                    "items": [unavailable(), unavailable()],
                }))
                .expect("the wrong-schema response serializes"),
                trace_id: Some(TRACE_ID.to_owned()),
            },
            RawEvidenceRequestBatchResponse {
                body: serde_json::to_vec(&serde_json::json!({
                    "schema": EVIDENCE_REQUEST_BATCH_SCHEMA_V1,
                    "type": "EvidenceRequestBatchResponse",
                    "items": [unavailable(), unavailable()],
                    "extra": true,
                }))
                .expect("the malformed response serializes"),
                trace_id: Some(TRACE_ID.to_owned()),
            },
        ];

        for response in responses {
            assert!(matches!(
                client.verify_batch_as_of(&prepared, &response, fixture.now),
                Err(EvidenceClientError::Protocol { status: 200, .. })
            ));
        }
    }

    #[tokio::test]
    async fn request_batch_response_enforces_its_independent_one_mib_ceiling() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = EvidenceClient::new(
            config_for(&server.uri(), &fixture)
                .with_max_response_bytes((MAX_EVIDENCE_REQUEST_BATCH_RESPONSE_BYTES * 2) as u64),
        )
        .expect("the client is configured");
        let prepared = client
            .prepare_batch(request_batch_spec(1))
            .expect("the request batch is prepared");
        Mock::given(method("POST"))
            .and(path("/v1/evidence/batch"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(
                        vec![b'x'; MAX_EVIDENCE_REQUEST_BATCH_RESPONSE_BYTES + 1],
                        EVIDENCE_REQUEST_BATCH_MEDIA_TYPE,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            client
                .send_batch(&prepared)
                .await
                .expect_err("the protocol ceiling is independent of a looser client bound"),
            EvidenceClientError::transport(TransportKind::ResponseTooLarge)
        );
    }

    /// The media-type grammar makes the type itself case-insensitive and a
    /// parameter no part of it. The problem contract is compared that way, and so
    /// is the success path, which shares the comparison: a deployment or an
    /// intermediary that spells the type differently or appends a charset is
    /// still answering with the contract's media type.
    #[tokio::test]
    async fn the_response_media_type_is_compared_without_its_case_or_parameters() {
        let fixture = signed_evidence();
        for media_type in [
            EVIDENCE_JWS_MEDIA_TYPE,
            "Application/JOSE+JSON",
            "application/jose+json; charset=utf-8",
        ] {
            let server = MockServer::start().await;
            let client = client_for(&server.uri(), &fixture);
            let prepared = client
                .prepare(spec(SubjectExpectations::AcceptFirstUse))
                .expect("the specification is accepted");
            Mock::given(method("POST"))
                .and(path("/v1/evidence"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                        .set_body_raw(fixture.sign(prepared.request_nonce()), media_type),
                )
                .mount(&server)
                .await;

            client
                .send(&prepared)
                .await
                .unwrap_or_else(|error| panic!("{media_type} was refused: {error}"));
        }
    }

    #[tokio::test]
    async fn the_prepared_format_selects_the_exact_sd_jwt_vc_exchange_and_verifier() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = client_for(&server.uri(), &fixture);
        let mut request_spec = spec(SubjectExpectations::AcceptFirstUse);
        request_spec.response_format = EvidenceResponseFormat::SdJwtVc;
        let prepared = client
            .prepare(request_spec)
            .expect("the SD-JWT VC request is prepared");
        let response = fixture.sign_sd_jwt_vc(prepared.request_nonce()).await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .and(header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(response, EVIDENCE_SD_JWT_VC_MEDIA_TYPE),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = client
            .send(&prepared)
            .await
            .expect("the SD-JWT VC response is read");
        client
            .verify_as_of(&prepared, &response, fixture.now)
            .expect("the SD-JWT VC response verifies");
    }

    /// Holder-key batch issuance keeps its own explicitly named API and media
    /// type alongside the independently verified request-batch API.
    #[tokio::test]
    async fn a_holder_bound_batch_request_reads_the_issuance_envelope() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = client_for(&server.uri(), &fixture);
        let mut request_spec = holder_bound_spec(EvidenceResponseFormat::SdJwtVcBatch);
        request_spec.holder_keys = vec![holder_key(), holder_key()];
        let prepared = client
            .prepare_holder_bound(request_spec)
            .expect("the batch request is prepared");
        let envelope = serde_json::json!({
            "schema": SD_JWT_VC_BATCH_SCHEMA_V1,
            "type": "SdJwtVcBatchEnvelope",
            "credentials": ["first-credential~", "second-credential~"],
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .and(header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(envelope, EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE),
            )
            .expect(1)
            .mount(&server)
            .await;

        let batch = client
            .send_holder_bound_batch(&prepared)
            .await
            .expect("the batch envelope is read");

        assert_eq!(batch.count(), 2);
        assert_eq!(
            batch.credential_for_holder_key(0),
            Some("first-credential~")
        );
        assert_eq!(
            batch.credential_for_holder_key(1),
            Some("second-credential~")
        );
    }

    /// Asking the client to verify a batch as one response is a category error,
    /// and the caller is told exactly that rather than shown a parse failure
    /// against an envelope nothing was ever going to verify.
    #[tokio::test]
    async fn verifying_a_batch_as_one_response_is_refused_legibly() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = client_for(&server.uri(), &fixture);
        let mut request_spec = spec(SubjectExpectations::AcceptFirstUse);
        request_spec.response_format = EvidenceResponseFormat::SdJwtVcBatch;
        request_spec.holder_keys = vec![holder_key()];
        let prepared = client
            .prepare(request_spec)
            .expect("the batch request is prepared");

        let failure = client
            .verify_as_of(&prepared, &raw(b"anything at all".to_vec()), fixture.now)
            .expect_err("an envelope is not one verifiable response");

        let EvidenceClientError::Configuration { reason } = &failure else {
            panic!("{failure:?}");
        };
        assert!(reason.contains("issuance packaging"), "{reason}");
        assert!(reason.contains("verify each credential"), "{reason}");
    }

    /// A body the problem contract does not cover leaves the client with nothing
    /// to say about the failure, which is exactly when the deployment's own
    /// identifier for the exchange matters. A header value outside the rule is
    /// still dropped rather than copied into the relying party's records.
    #[tokio::test]
    async fn a_failure_carries_the_correlation_identifier_even_with_an_unreadable_body() {
        let fixture = signed_evidence();
        for (sent, expected) in [
            (TRACEPARENT, Some(TRACE_ID.to_owned())),
            ("01AB role=subject", None),
        ] {
            let server = MockServer::start().await;
            let client = client_for(&server.uri(), &fixture);
            let prepared = client
                .prepare(spec(SubjectExpectations::AcceptFirstUse))
                .expect("the specification is accepted");
            Mock::given(method("POST"))
                .and(path("/v1/evidence"))
                .respond_with(
                    ResponseTemplate::new(400)
                        .insert_header(TRACEPARENT_HEADER, sent)
                        .set_body_raw(b"<html>a gateway wrote this</html>".to_vec(), "text/html"),
                )
                .mount(&server)
                .await;

            assert_eq!(
                client
                    .send(&prepared)
                    .await
                    .expect_err("a body outside the contract is a protocol failure"),
                EvidenceClientError::Protocol {
                    status: 400,
                    code: None,
                    trace_id: expected,
                    retry_after_seconds: None,
                },
                "the header carried {sent:?}"
            );
        }
    }

    /// The four ways a bounded read can fail are four different things to tell an
    /// adopter. A timeout while the body streams is the likely one, because the
    /// request timeout runs until the body finishes, and reporting it as an
    /// oversized response would send the adopter to the wrong place.
    #[tokio::test]
    async fn a_failed_body_read_reports_its_own_cause() {
        for error in [
            BoundedReadError::ContentLengthExceeded {
                content_length: 2,
                max_bytes: 1,
            },
            BoundedReadError::BodyTooLarge { max_bytes: 1 },
            BoundedReadError::LengthOverflow,
        ] {
            assert_eq!(
                read_failure_kind(&error),
                TransportKind::ResponseTooLarge,
                "{error}"
            );
        }

        let fixture = signed_evidence();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;
        let http = build_client(
            &config_for(&server.uri(), &fixture).with_request_timeout(Duration::from_millis(100)),
        )
        .expect("the outbound client builds");
        let timeout = http
            .get(server.uri())
            .send()
            .await
            .expect_err("the request timeout elapses");
        assert!(timeout.is_timeout(), "{timeout:?}");
        assert_eq!(
            read_failure_kind(&BoundedReadError::Transport(timeout)),
            TransportKind::Timeout
        );

        let refused = http
            .get(closed_loopback_origin())
            .send()
            .await
            .expect_err("nothing is listening");
        assert!(!refused.is_timeout(), "{refused:?}");
        assert_eq!(
            read_failure_kind(&BoundedReadError::Transport(refused)),
            TransportKind::Exchange
        );
    }

    /// One discovery document, minimal but complete: the schema discriminator is
    /// what these two tests vary, and an empty entitlement list is a shape the
    /// definitions contract permits.
    fn definitions_json(schema: &str) -> String {
        format!(
            r#"{{"schema":"{schema}","assuranceProfile":"local","audience":"urn:example:client:audience:relying-party","issuedBy":"urn:example:client:issuer","providedBy":"urn:example:client:provider","definitions":[]}}"#
        )
    }

    fn definitions_json_with_batch_maximum(value: u16) -> String {
        definitions_json(EVIDENCE_DEFINITIONS_SCHEMA_V1).replace(
            r#","definitions"#,
            &format!(r#", "holderBoundBatchMaxSize":{value},"definitions"#),
        )
    }

    async fn discovery_client(
        server: &MockServer,
        fixture: &SignedEvidenceFixture,
        body: String,
    ) -> EvidenceClient {
        discovery_client_with(server, fixture, body, |config| config).await
    }

    async fn discovery_client_with(
        server: &MockServer,
        fixture: &SignedEvidenceFixture,
        body: String,
        bounds: impl FnOnce(EvidenceClientConfig) -> EvidenceClientConfig,
    ) -> EvidenceClient {
        Mock::given(method("GET"))
            .and(path("/v1/evidence-definitions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(body.into_bytes(), JSON_MEDIA_TYPE),
            )
            .mount(server)
            .await;
        EvidenceClient::new(bounds(config_for(&server.uri(), fixture)))
            .expect("the client is configured")
    }

    /// The signed response bound is derived from what the verifier will accept as
    /// a signed response, and discovery is neither signed nor verified. A relying
    /// party that tightens the response bound to what its own assertions need must
    /// keep being able to read discovery, and one that raises the discovery bound
    /// for a deployment publishing many definitions must not thereby accept a
    /// larger signed body than it decided to.
    #[tokio::test]
    async fn the_metadata_bound_is_not_the_signed_response_bound() {
        let fixture = signed_evidence();
        let document = definitions_json(EVIDENCE_DEFINITIONS_SCHEMA_V1);
        let document_bytes = document.len() as u64;

        let server = MockServer::start().await;
        let client = discovery_client_with(&server, &fixture, document.clone(), |config| {
            config.with_max_response_bytes(1)
        })
        .await;
        let read = client
            .discover()
            .await
            .expect("the signed response bound does not reach discovery");
        assert_eq!(read.schema, EVIDENCE_DEFINITIONS_SCHEMA_V1);

        let server = MockServer::start().await;
        let client = discovery_client_with(&server, &fixture, document, |config| {
            config.with_max_metadata_bytes(document_bytes - 1)
        })
        .await;
        assert_eq!(
            client
                .discover()
                .await
                .expect_err("a document past the metadata bound is not read"),
            EvidenceClientError::transport(TransportKind::ResponseTooLarge)
        );
    }

    /// Discovery is authoring input, so a document announcing a schema version
    /// this client does not understand must not become authoring input anyway.
    /// These Rust types would accept a later document that happens to fit them,
    /// and the relying party would then author requests for a shape whose meaning
    /// it guessed.
    #[tokio::test]
    async fn a_discovery_document_announcing_another_schema_is_a_protocol_failure() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = discovery_client(
            &server,
            &fixture,
            definitions_json("registry.evidence-definitions/v2"),
        )
        .await;

        assert_eq!(
            client
                .discover()
                .await
                .expect_err("the announced schema is not the one this client reads"),
            EvidenceClientError::Protocol {
                status: 200,
                code: None,
                // The response trace identifier survives, so an adopter has
                // something to quote when the versions disagree.
                trace_id: Some(TRACE_ID.to_owned()),
                retry_after_seconds: None,
            }
        );
    }

    #[tokio::test]
    async fn a_discovery_document_announcing_the_read_schema_is_accepted() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = discovery_client(
            &server,
            &fixture,
            definitions_json(EVIDENCE_DEFINITIONS_SCHEMA_V1),
        )
        .await;

        let document = client
            .discover()
            .await
            .expect("the document is the v1 shape");
        assert_eq!(document.schema, EVIDENCE_DEFINITIONS_SCHEMA_V1);
        assert!(document.definitions.is_empty());
    }

    #[tokio::test]
    async fn a_discovered_holder_bound_batch_maximum_outside_the_contract_is_a_protocol_failure() {
        let fixture = signed_evidence();
        for value in [0, 17, u16::MAX] {
            let server = MockServer::start().await;
            let client = discovery_client(
                &server,
                &fixture,
                definitions_json_with_batch_maximum(value),
            )
            .await;

            assert_eq!(
                client
                    .discover()
                    .await
                    .expect_err("an invalid batch maximum is not authoring input"),
                EvidenceClientError::Protocol {
                    status: 200,
                    code: None,
                    trace_id: Some(TRACE_ID.to_owned()),
                    retry_after_seconds: None,
                },
                "a ceiling of {value} must be refused"
            );
        }
    }

    /// `Retry-After` is a response-controlled value, and the client documents the
    /// wait it reports as actionable. A hostile or misconfigured hop answering with
    /// a day would have a caller that honors it stop for a day, and a zero would
    /// invite an immediate retry loop, so only a wait a relying party would
    /// plausibly honor is reported at all.
    #[tokio::test]
    async fn a_wait_the_transient_contract_does_not_bound_is_not_reported_as_actionable() {
        let bound = MAXIMUM_RETRY_AFTER_SECONDS.to_string();
        for (header, expected_wait) in [
            ("1", Some(1)),
            (bound.as_str(), Some(MAXIMUM_RETRY_AFTER_SECONDS)),
            ("0", None),
            ("86400", None),
            // The field grammar also permits an HTTP date, which this client has
            // never read and must not read as a count of seconds.
            ("Fri, 31 Dec 1999 23:59:59 GMT", None),
        ] {
            let fixture = signed_evidence();
            let server = MockServer::start().await;
            let client = client_for(&server.uri(), &fixture);
            let prepared = client
                .prepare(spec(SubjectExpectations::AcceptFirstUse))
                .expect("the specification is accepted");
            Mock::given(method("POST"))
                .and(path("/v1/evidence"))
                .respond_with(
                    ResponseTemplate::new(429)
                        .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                        .insert_header(RETRY_AFTER.as_str(), header)
                        .set_body_raw(
                            format!(
                                r#"{{"type":"https://id.registrystack.org/problems/registry-evidence/evidence/rate_limited","title":"Evidence request rate is exhausted","status":429,"detail":"the Evidence request rate is exhausted","code":"evidence.rate_limited","traceId":"{TRACE_ID}"}}"#
                            )
                            .into_bytes(),
                            "application/problem+json",
                        ),
                )
                .mount(&server)
                .await;

            assert_eq!(
                client
                    .send(&prepared)
                    .await
                    .expect_err("the deployment refused the request"),
                EvidenceClientError::Denied {
                    status: 429,
                    code: "evidence.rate_limited".to_owned(),
                    trace_id: Some(TRACE_ID.to_owned()),
                    retry_after_seconds: expected_wait,
                },
                "the wait reported for a `Retry-After` of {header}"
            );
        }
    }

    /// A gateway can answer a refusal with a body far larger than the contract's,
    /// and the read then fails. The status and the deployment's identifier were
    /// already in hand, so the failure still carries the support workflow this
    /// crate advertises.
    #[tokio::test]
    async fn a_refusal_whose_body_cannot_be_read_keeps_its_status_and_identifier() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client =
            EvidenceClient::new(config_for(&server.uri(), &fixture).with_max_response_bytes(32))
                .expect("the client is configured");
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .respond_with(
                ResponseTemplate::new(502)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(vec![b'a'; 4096], "text/html"),
            )
            .mount(&server)
            .await;

        assert_eq!(
            client
                .send(&prepared)
                .await
                .expect_err("the body is beyond the bound"),
            EvidenceClientError::Protocol {
                status: 502,
                code: None,
                trace_id: Some(TRACE_ID.to_owned()),
                retry_after_seconds: None,
            }
        );
    }

    /// An answer the deployment meant as a success, whose body cannot be read, is
    /// a transport failure: there is no status or code worth reporting, only the
    /// reason the bytes never arrived.
    #[tokio::test]
    async fn a_successful_answer_whose_body_cannot_be_read_is_a_transport_failure() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client =
            EvidenceClient::new(config_for(&server.uri(), &fixture).with_max_response_bytes(32))
                .expect("the client is configured");
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(vec![b'a'; 4096], EVIDENCE_JWS_MEDIA_TYPE),
            )
            .mount(&server)
            .await;

        assert_eq!(
            client
                .send(&prepared)
                .await
                .expect_err("the body is beyond the bound"),
            EvidenceClientError::transport(TransportKind::ResponseTooLarge)
        );
    }

    /// A deployment that is not listening is a connection failure, not a refusal
    /// and not a protocol fault.
    #[tokio::test]
    async fn an_unreachable_deployment_reports_a_connection_failure() {
        let fixture = signed_evidence();
        let client = client_for(&closed_loopback_origin(), &fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");

        assert_eq!(
            client
                .send(&prepared)
                .await
                .expect_err("nothing is listening"),
            EvidenceClientError::transport(TransportKind::Connect)
        );
    }

    /// The configured total timeout is the relying party's own bound on how long
    /// a decision may wait.
    #[tokio::test]
    async fn an_elapsed_request_timeout_reports_a_timeout() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;
        let client = EvidenceClient::new(
            config_for(&server.uri(), &fixture).with_request_timeout(Duration::from_millis(100)),
        )
        .expect("the client is configured");
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");

        assert_eq!(
            client
                .send(&prepared)
                .await
                .expect_err("the deployment answers too late"),
            EvidenceClientError::transport(TransportKind::Timeout)
        );
    }

    /// Pinning the certificate authorities replaces the platform store, so
    /// material the client cannot use has to fail at construction. Falling back to
    /// the platform store would quietly widen who may vouch for the deployment.
    #[tokio::test]
    async fn unusable_pinned_certificate_material_is_refused_at_construction() {
        let fixture = signed_evidence();
        for (bundle, reasons) in [
            (
                b"".to_vec(),
                Some(&["the pinned certificate authority bundle carries no certificate"][..]),
            ),
            (
                b"not a certificate".to_vec(),
                Some(&["the pinned certificate authority bundle carries no certificate"][..]),
            ),
            // PEM framing over base64 that decodes to nothing a certificate parser
            // accepts. Which layer refuses it depends on the TLS backend the
            // build's feature resolution left enabled: one rejects the content
            // while the bundle is read, another while the outbound client is
            // built. Either way it is refused at construction, which is the
            // property that keeps the platform store from quietly taking over.
            // The reason is left unpinned for this one row: it is Cargo's
            // feature unification across the workspace that picks the layer,
            // not anything this crate controls, so only the variant is
            // asserted.
            (
                b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"
                    .to_vec(),
                None,
            ),
            // A framed block whose body is outside the base64 alphabet fails
            // while the bundle is being read, which is the one refusal that
            // names the PEM itself.
            (
                b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_vec(),
                Some(&["the pinned certificate authority bundle is not readable PEM"][..]),
            ),
        ] {
            let error = EvidenceClient::new(
                config_for("https://evidence.example.org", &fixture)
                    .with_trusted_root_certificates(bundle.clone()),
            )
            .map(|_| ())
            .expect_err("unusable trust material is refused");
            let EvidenceClientError::Configuration { reason } = error else {
                panic!("unusable trust material is a configuration failure: {error}");
            };
            if let Some(reasons) = reasons {
                assert!(
                    reasons.contains(&reason),
                    "{:?} was refused as {reason}",
                    String::from_utf8_lossy(&bundle)
                );
            }
        }
    }

    /// A redirect is not part of the response contract. Following one would carry
    /// the credential to a host the relying party never configured, so the client
    /// reports the answer as it stands and sends nothing onward.
    #[tokio::test]
    async fn a_redirect_is_refused_and_the_credential_never_follows_it() {
        let fixture = signed_evidence();
        let elsewhere = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).insert_header(TRACEPARENT_HEADER, TRACEPARENT))
            .mount(&elsewhere)
            .await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("{}/v1/evidence", elsewhere.uri()).as_str(),
            ))
            .mount(&server)
            .await;
        let client = client_for(&server.uri(), &fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");

        assert_eq!(
            client
                .send(&prepared)
                .await
                .expect_err("a redirect is not an Evidence response"),
            EvidenceClientError::Protocol {
                status: 302,
                code: None,
                trace_id: None,
                retry_after_seconds: None,
            }
        );
        assert!(
            elsewhere
                .received_requests()
                .await
                .expect("the stub records what it received")
                .is_empty(),
            "the credential must not follow a redirect"
        );
    }

    /// An adopter's own user agent is how a deployment operator recognizes the
    /// relying party in its logs, so it has to reach the wire.
    #[tokio::test]
    async fn the_configured_user_agent_reaches_the_deployment() {
        let fixture = signed_evidence();
        let server = MockServer::start().await;
        let client = EvidenceClient::new(
            config_for(&server.uri(), &fixture).with_user_agent("relying-party/1.0"),
        )
        .expect("the client is configured");
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the specification is accepted");
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .and(header("user-agent", "relying-party/1.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(
                        fixture.sign(prepared.request_nonce()),
                        EVIDENCE_JWS_MEDIA_TYPE,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        client
            .send(&prepared)
            .await
            .expect("the deployment recognized the user agent");
    }

    #[test]
    fn debug_output_never_carries_a_response_body_or_a_credential() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("test-token"), "{rendered}");

        let response = raw(b"a-signed-response-canary".to_vec());
        let rendered = format!("{response:?}");
        assert!(!rendered.contains("canary"), "{rendered}");
        assert!(rendered.contains("body_bytes"), "{rendered}");
    }

    fn holder_bound_spec(response_format: EvidenceResponseFormat) -> HolderBoundRequestSpec {
        let spec = spec(SubjectExpectations::AcceptFirstUse);
        HolderBoundRequestSpec {
            response_format,
            requirement: spec.requirement,
            purpose: spec.purpose,
            evidence_type: spec.evidence_type,
            issued_by: spec.issued_by,
            provided_by: spec.provided_by,
            configuration_revision: spec.configuration_revision,
            expected_assurance_profile: spec.expected_assurance_profile,
            subjects: spec.subjects,
            holder_keys: vec![holder_key()],
            expected_outputs: spec.expected_outputs,
            maximum_assertion_lifetime_seconds: spec.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: spec.clock_skew_seconds,
            subject_expectations: spec.subject_expectations,
        }
    }

    fn non_verifying_client(base_url: &str) -> NonVerifyingEvidenceClient {
        NonVerifyingEvidenceClient::new(EvidenceClientConfig::without_verification(
            Url::parse(base_url).expect("the base URL parses"),
            Arc::new(StaticToken::new("test-token").expect("the credential is accepted")),
        ))
        .expect("the non-verifying client is configured")
    }

    /// A holder-bound request negotiates the same media type a holder-bound
    /// credential is returned in, and what comes back is read rather than
    /// judged. There is no verification step to reach here, at this client or
    /// any other.
    #[tokio::test]
    async fn a_holder_bound_request_reaches_the_deployment_and_the_answer_is_read_unjudged() {
        let server = MockServer::start().await;
        let client = non_verifying_client(&server.uri());
        let prepared = client
            .prepare_holder_bound(holder_bound_spec(EvidenceResponseFormat::SdJwtVc))
            .expect("the holder-bound request is prepared");
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .and(header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(
                        b"a-holder-bound-credential~".to_vec(),
                        EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = client
            .send_holder_bound(&prepared)
            .await
            .expect("the credential is read");
        assert_eq!(response.body(), b"a-holder-bound-credential~");
    }

    /// The single-send rule is the audience-scoped rule, and it holds through
    /// the client rather than only inside the prepared request.
    #[tokio::test]
    async fn a_prepared_holder_bound_request_reaches_the_deployment_at_most_once() {
        let server = MockServer::start().await;
        let client = non_verifying_client(&server.uri());
        let prepared = client
            .prepare_holder_bound(holder_bound_spec(EvidenceResponseFormat::SdJwtVc))
            .expect("the holder-bound request is prepared");
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(TRACEPARENT_HEADER, TRACEPARENT)
                    .set_body_raw(
                        b"a-holder-bound-credential~".to_vec(),
                        EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;

        client
            .send_holder_bound(&prepared)
            .await
            .expect("the first send reaches the deployment");
        let failure = client
            .send_holder_bound(&prepared)
            .await
            .expect_err("the second send is refused");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "a prepared request may be sent once; prepare again for a fresh nonce"
                }
            ),
            "{failure:?}"
        );
    }

    /// The batch rule reads one format and one only, on this path exactly as on
    /// the audience-scoped one, so the single send is not spent on an answer
    /// this method could not read.
    #[tokio::test]
    async fn send_holder_bound_batch_refuses_a_request_that_did_not_ask_for_a_batch() {
        let server = MockServer::start().await;
        let client = non_verifying_client(&server.uri());
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).insert_header(TRACEPARENT_HEADER, TRACEPARENT))
            .expect(0)
            .mount(&server)
            .await;
        let prepared = client
            .prepare_holder_bound(holder_bound_spec(EvidenceResponseFormat::SdJwtVc))
            .expect("the singular request is prepared");

        let failure = client
            .send_holder_bound_batch(&prepared)
            .await
            .expect_err("a singular request is not a batch");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "this prepared request did not ask for a batch response format"
                }
            ),
            "{failure:?}"
        );
    }

    /// The two constructors decide the two stances, and neither accepts the
    /// other's configuration. A client that verifies always has the key set its
    /// verification methods read, and a client that does not verify never
    /// reaches a method that would pretend to.
    #[test]
    fn a_client_that_verifies_and_one_that_does_not_are_not_interchangeable() {
        let fixture = signed_evidence();
        let failure = EvidenceClient::new(EvidenceClientConfig::without_verification(
            Url::parse("https://evidence.example.org/").expect("the base URL parses"),
            Arc::new(StaticToken::new("test-token").expect("the credential is accepted")),
        ))
        .expect_err("a verifying client refuses a declined configuration");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "this client verifies, so its configuration must pin a key set"
                }
            ),
            "{failure:?}"
        );

        let failure =
            NonVerifyingEvidenceClient::new(config_for("https://evidence.example.org/", &fixture))
                .expect_err("a non-verifying client refuses a pinned configuration");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason:
                        "this client does not verify, so its configuration must decline verification"
                }
            ),
            "{failure:?}"
        );
    }

    /// The non-verifying client carries no key material at all, so there is
    /// nothing for a verification path to have been built on even if one were
    /// added by accident. The compiler enforces the absence of the path; this
    /// records the absence of what it would need.
    #[test]
    fn a_non_verifying_client_holds_nothing_to_verify_with() {
        let client = non_verifying_client("https://evidence.example.org/");
        assert!(!client.config().verifies());
        assert!(client.config().trusted_jwks().keys.is_empty());
        assert!(client.config().revoked_key_ids().is_empty());
    }

    #[test]
    fn metadata_cache_policy_honors_no_store_and_the_profile_ceiling() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            metadata_cache_seconds(&headers, 600, None).expect("default"),
            600
        );
        assert_eq!(
            metadata_cache_seconds(&headers, 600, Some(17)).expect("retained default"),
            17
        );

        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=90"),
        );
        assert_eq!(
            metadata_cache_seconds(&headers, 600, None).expect("lower max"),
            90
        );

        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=900"),
        );
        assert_eq!(
            metadata_cache_seconds(&headers, 600, None).expect("bounded max"),
            600
        );

        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        assert_eq!(
            metadata_cache_seconds(&headers, 600, None).expect("no store"),
            0
        );

        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        assert_eq!(
            metadata_cache_seconds(&headers, 600, Some(90)).expect("no cache"),
            0
        );
    }

    #[test]
    fn stale_metadata_never_outlives_the_profile_cache_ceiling() {
        let now = Instant::now();
        let (expires_at, stale_until) = cache_deadlines(now, 60, 600);
        assert_eq!(expires_at.duration_since(now), Duration::from_secs(60));
        assert_eq!(stale_until.duration_since(now), Duration::from_secs(600));

        let (expires_at, stale_until) = cache_deadlines(now, 900, 600);
        assert_eq!(expires_at.duration_since(now), Duration::from_secs(600));
        assert_eq!(stale_until.duration_since(now), Duration::from_secs(600));

        let (expires_at, stale_until) = cache_deadlines(now, 0, 600);
        assert_eq!(expires_at, now);
        assert_eq!(stale_until, now);
    }

    #[test]
    fn metadata_etags_are_strong_bounded_and_unambiguous() {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("\"revision-1\""));
        assert_eq!(
            metadata_etag(&headers)
                .expect("strong ETag")
                .expect("present ETag"),
            HeaderValue::from_static("\"revision-1\"")
        );
        for invalid in ["W/\"weak\"", "unquoted"] {
            headers.insert(ETAG, HeaderValue::from_str(invalid).expect("header value"));
            assert!(metadata_etag(&headers).is_err(), "{invalid} was accepted");
        }
    }

    #[test]
    fn strict_discovery_refuses_metadata_hosts_that_resolve_locally() {
        let policy = FetchUrlPolicy::strict();
        for target in [
            "https://127.0.0.1/token",
            "https://10.0.0.1/token",
            "https://[::1]/token",
            "https://localhost/token",
        ] {
            assert!(
                policy
                    .validate_dns_pinned_for_immediate_fetch(&Url::parse(target).expect("test URL"))
                    .is_err(),
                "{target} was accepted"
            );
        }
    }

    #[test]
    fn local_discovery_accepts_only_exact_numeric_http_loopback_authorization_urls() {
        for target in ["http://127.0.0.1:8081", "http://127.0.0.1:8081/token"] {
            let url = Url::parse(target).expect("numeric loopback URL");
            assert!(
                validate_metadata_url(&url, &TrustProfile::LocalLoopbackDiscovery).is_ok(),
                "{target} was rejected"
            );
            assert!(FetchUrlPolicy::dev()
                .validate_dns_pinned_for_immediate_fetch(&url)
                .is_ok());
        }

        // These values come from protected-resource and authorization-server
        // metadata before a token provider exists. Refusing them here prevents
        // an unauthenticated tutorial endpoint from obtaining a real remote
        // access token and receiving it as the Evidence bearer credential.
        for target in [
            "https://issuer.example.org",
            "https://tokens.example.net/oauth/token",
            "https://127.0.0.1:8081/token",
            "http://localhost:8081/token",
            "http://[::1]:8081/token",
            "http://10.0.0.1:8081/token",
            "http://127.0.0.1/token",
            "http://127.0.0.1:0/token",
        ] {
            assert!(
                validate_metadata_url(
                    &Url::parse(target).expect("rejected authorization URL parses"),
                    &TrustProfile::LocalLoopbackDiscovery,
                )
                .is_err(),
                "{target} was accepted before token acquisition"
            );
        }
    }

    #[test]
    fn authorization_server_issuer_must_match_the_announced_string_exactly() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://issuer.example.org/tenant".to_owned(),
            token_endpoint: "https://tokens.example.net/oauth/token".to_owned(),
            grant_types_supported: vec!["client_credentials".to_owned()],
            token_endpoint_auth_methods_supported: vec!["private_key_jwt".to_owned()],
        };
        assert!(authorization_server_metadata_is_compatible(
            &metadata,
            "https://issuer.example.org/tenant"
        ));
        for mismatch in [
            "https://issuer.example.org/tenant/",
            "https://ISSUER.example.org/tenant",
            "https://issuer.example.org:443/tenant",
        ] {
            assert!(
                !authorization_server_metadata_is_compatible(&metadata, mismatch),
                "{mismatch} was treated as the exact issuer"
            );
        }
    }

    #[test]
    fn authorization_server_metadata_uses_the_rfc_8414_path_construction() {
        assert_eq!(
            metadata_endpoint(&Url::parse("https://issuer.example.org").expect("root issuer URL"))
                .expect("root metadata URL")
                .as_str(),
            "https://issuer.example.org/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            metadata_endpoint(
                &Url::parse("https://issuer.example.org/tenant/one").expect("path issuer URL")
            )
            .expect("path metadata URL")
            .as_str(),
            "https://issuer.example.org/.well-known/oauth-authorization-server/tenant/one"
        );
    }

    #[tokio::test]
    async fn cached_public_metadata_revalidates_with_the_exact_strong_etag() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .and(header("if-none-match", "\"revision-1\""))
            .respond_with(ResponseTemplate::new(304).insert_header("etag", "\"revision-1\""))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "Application/JSON; Charset=UTF-8")
                    .insert_header("cache-control", "public, max-age=60")
                    .insert_header("etag", "\"revision-1\"")
                    .set_body_json(serde_json::json!({"value": "retained"})),
            )
            .with_priority(10)
            .expect(1)
            .mount(&server)
            .await;
        let fixture = signed_evidence();
        let client = client_for(&server.uri(), &fixture);
        let url = Url::parse(&format!("{}/metadata", server.uri())).expect("metadata URL");
        let first: PublicDocument<serde_json::Value> = client
            .public_json(
                url.clone(),
                JSON_MEDIA_TYPE,
                None,
                600,
                &FetchUrlPolicy::dev(),
            )
            .await
            .expect("first metadata response");
        let second = client
            .public_json(
                url,
                JSON_MEDIA_TYPE,
                Some((&first.value, first.etag.as_ref(), first.cache_seconds)),
                600,
                &FetchUrlPolicy::dev(),
            )
            .await
            .expect("conditional metadata response");
        assert_eq!(first.value, second.value);
        assert_eq!(second.cache_seconds, 60);
    }

    #[tokio::test]
    async fn public_metadata_redirects_are_not_followed() {
        let elsewhere = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", JSON_MEDIA_TYPE)
                    .set_body_json(serde_json::json!({"value": "attacker-selected"})),
            )
            .mount(&elsewhere)
            .await;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/metadata", elsewhere.uri()).as_str()),
            )
            .mount(&server)
            .await;
        let fixture = signed_evidence();
        let client = client_for(&server.uri(), &fixture);
        let url = Url::parse(&format!("{}/metadata", server.uri())).expect("metadata URL");

        assert!(client
            .public_json::<serde_json::Value>(
                url,
                JSON_MEDIA_TYPE,
                None,
                600,
                &FetchUrlPolicy::dev(),
            )
            .await
            .is_err());
        assert!(
            elsewhere
                .received_requests()
                .await
                .expect("the redirect target records requests")
                .is_empty(),
            "metadata fetch must not follow a redirect"
        );
    }
}

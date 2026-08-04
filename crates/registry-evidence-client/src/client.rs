//! The HTTP client: one request, one offline verification.
//!
//! Every exchange here is bounded and unretried. The only judgement the client
//! makes about a response is the one the portable verifier makes for it, against
//! the policy the caller closed before the request existed.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use registry_evidence_verifier::{
    model::{Evidence, FlattenedJws, JwksDocument, SubjectBinding},
    verifier::{verify_flattened_jws, ExpectedSubjectDocument},
    EVIDENCE_JWS_MEDIA_TYPE,
};
use registry_platform_httputil::{read_bounded, BoundedReadError};
use reqwest::{
    header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER},
    Method, StatusCode,
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::EvidenceClientConfig,
    definitions::EvidenceDefinitionsDocument,
    error::{EvidenceClientError, TransportKind},
    prepare::{EvidenceRequestSpec, PreparedEvidenceRequest, SubjectExpectations},
    problem::{essence, map_problem, sanitized_operation},
    request::EvidenceRequestBody,
};

/// Path of the Evidence request endpoint.
const EVIDENCE_PATH: &str = "v1/evidence";
/// Path of the requester-scoped discovery endpoint.
const DEFINITIONS_PATH: &str = "v1/evidence-definitions";
/// Path of the published verification key set.
const JWKS_PATH: &str = ".well-known/evidence/jwks.json";

const JSON_MEDIA_TYPE: &str = "application/json";
const JWKS_MEDIA_TYPE: &str = "application/jwk-set+json";

/// The opaque per-request identifier the deployment returns.
const CORRELATION_HEADER: &str = "x-request-id";

/// Whether an exchange carries the relying party's bearer credential.
///
/// Named rather than a boolean, so a call site states which of the two it means
/// instead of leaving the reader to recover it from a bare `true`.
enum Credential {
    Required,
    None,
}

/// A relying party's connection to one Evidence deployment.
#[derive(Debug)]
pub struct EvidenceClient {
    config: EvidenceClientConfig,
    http: reqwest::Client,
}

/// A signed response, read but not yet judged.
///
/// It exists so a relying party can retain the exact bytes it verified. Nothing
/// in it has been trusted yet.
#[derive(Clone)]
pub struct RawEvidenceResponse {
    body: Vec<u8>,
    operation: Option<String>,
}

impl RawEvidenceResponse {
    /// The signed response bytes, exactly as received.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The deployment's opaque identifier for this exchange, for support
    /// correlation.
    #[must_use]
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }
}

impl std::fmt::Debug for RawEvidenceResponse {
    /// The body is unverified, potentially subject-identifying material, so only
    /// its length and the correlation identifier are rendered.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawEvidenceResponse")
            .field("body_bytes", &self.body.len())
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

/// A response that satisfied every expectation.
#[derive(Debug, Clone)]
pub struct VerifiedEvidence {
    evidence: Evidence,
    operation: Option<String>,
}

impl VerifiedEvidence {
    /// The verified payload.
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The deployment's opaque identifier for the exchange that produced this
    /// payload.
    #[must_use]
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
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
    pub fn new(config: EvidenceClientConfig) -> Result<Self, EvidenceClientError> {
        config.validate()?;
        let http = build_client(&config)?;
        Ok(Self { config, http })
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
        PreparedEvidenceRequest::new(spec)
    }

    /// Read the request shapes this requester is entitled to send.
    ///
    /// Discovery is authoring input, not a trust anchor. It tells a relying
    /// party what it may ask for; it never supplies verification expectations
    /// for a request already in flight.
    pub async fn discover(&self) -> Result<EvidenceDefinitionsDocument, EvidenceClientError> {
        self.get_json(DEFINITIONS_PATH, JSON_MEDIA_TYPE, Credential::Required)
            .await
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
        self.get_json(JWKS_PATH, JWKS_MEDIA_TYPE, Credential::None)
            .await
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
        let url = self.endpoint(EVIDENCE_PATH)?;
        let body = serialize_request(prepared.body())?;
        let request = self
            .http
            .request(Method::POST, url)
            .header(ACCEPT, EVIDENCE_JWS_MEDIA_TYPE)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .body(body);
        let response = self.exchange(request, Credential::Required).await?;
        self.expect_success(response, EVIDENCE_JWS_MEDIA_TYPE).await
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
    /// The parameter is a [`chrono::DateTime<Utc>`], the same instant type the
    /// portable verifier's own policy takes.
    pub fn verify_as_of(
        &self,
        prepared: &PreparedEvidenceRequest,
        response: &RawEvidenceResponse,
        now: DateTime<Utc>,
    ) -> Result<VerifiedEvidence, EvidenceClientError> {
        let policy_document = match prepared.subject_expectations() {
            SubjectExpectations::Pinned(_) => prepared.policy_document().clone(),
            // Adopt the response's own role-bound bindings as expectations, then
            // let the ordinary verifier apply the whole policy. Nothing else is
            // taken from the response, and the subject question is deliberately
            // deferred to the caller, which persists these bindings and pins
            // them next time.
            SubjectExpectations::AcceptFirstUse => {
                prepared.policy_with_subjects(untrusted_subject_bindings(&response.body))
            }
        };
        let policy = policy_document.into_policy(now);
        let evidence = verify_flattened_jws(&response.body, &self.config.trusted_jwks, &policy)
            .map_err(EvidenceClientError::Verification)?;
        Ok(VerifiedEvidence {
            evidence,
            operation: response.operation.clone(),
        })
    }

    /// Read one JSON document from a GET endpoint under the base URL.
    ///
    /// The two documents this serves, discovery and the published key set, are
    /// both authoring input rather than verification input, and a body that does
    /// not parse is a protocol failure rather than a refusal: the deployment
    /// answered, and the answer was not the document it promised.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        media_type: &str,
        credential: Credential,
    ) -> Result<T, EvidenceClientError> {
        let url = self.endpoint(path)?;
        let request = self
            .http
            .request(Method::GET, url)
            .header(ACCEPT, media_type);
        let response = self.exchange(request, credential).await?;
        let body = self.expect_success(response, media_type).await?;
        serde_json::from_slice(&body.body).map_err(|_| EvidenceClientError::Protocol {
            status: StatusCode::OK.as_u16(),
            code: None,
            operation: body.operation,
            retry_after_seconds: None,
        })
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
                // The plaintext credential exists in one scrubbed buffer here.
                // The header value reqwest owns afterwards cannot be zeroized,
                // which is why it is marked sensitive below.
                let mut header = Zeroizing::new(String::with_capacity(7 + token.expose().len()));
                header.push_str("Bearer ");
                header.push_str(token.expose());
                let mut value = HeaderValue::from_str(&header).map_err(|_| {
                    EvidenceClientError::configuration(
                        "the credential is not a usable header value",
                    )
                })?;
                // The credential must never reach a diagnostic, and reqwest
                // honors this marking when it formats a request.
                value.set_sensitive(true);
                request.header(AUTHORIZATION, value)
            }
            Credential::None => request,
        };
        request.send().await.map_err(|error| {
            let kind = if error.is_timeout() {
                TransportKind::Timeout
            } else if error.is_connect() {
                // TLS negotiation failures arrive here too. Separating them
                // would mean reading a transport error chain whose text this
                // crate must not copy into a diagnostic.
                TransportKind::Connect
            } else {
                TransportKind::Exchange
            };
            EvidenceClientError::transport(kind)
        })
    }

    /// Read a successful response of exactly one media type, or map the
    /// deployment's answer onto a client failure.
    async fn expect_success(
        &self,
        response: reqwest::Response,
        expected_media_type: &str,
    ) -> Result<RawEvidenceResponse, EvidenceClientError> {
        let status = response.status().as_u16();
        let operation = response
            .headers()
            .get(CORRELATION_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(sanitized_operation);
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let retry_after_seconds = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());

        let body = match read_bounded(response, self.config.max_response_bytes).await {
            Ok(body) => body,
            // The status and the correlation identifier arrived before the body
            // did. A refusal keeps them, because they are the whole support
            // workflow this crate offers and the unread body would have carried
            // nothing else the caller may act on.
            Err(_) if !(200..300).contains(&status) => {
                return Err(EvidenceClientError::Protocol {
                    status,
                    code: None,
                    operation,
                    retry_after_seconds: None,
                })
            }
            // An answer meant as a success has no status or code worth
            // reporting, only the reason its bytes never arrived.
            Err(error) => return Err(EvidenceClientError::transport(read_failure_kind(&error))),
        };

        if !(200..300).contains(&status) {
            return Err(map_problem(
                status,
                media_type.as_deref(),
                &body,
                retry_after_seconds,
                operation.as_deref(),
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
                operation,
                retry_after_seconds: None,
            });
        }
        Ok(RawEvidenceResponse { body, operation })
    }
}

/// Build the outbound client.
fn build_client(config: &EvidenceClientConfig) -> Result<reqwest::Client, EvidenceClientError> {
    let mut builder = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .connect_timeout(config.connect_timeout)
        // A redirect is not part of the response contract, and following one
        // would present the relying party's credential to a host the integrator
        // never configured, on the say-so of a response header. The answer is
        // reported as it stands instead.
        .redirect(reqwest::redirect::Policy::none())
        // The proxy environment variables are ignored deliberately. An ambient
        // variable would otherwise route a credential through an intermediary the
        // integrator did not choose, and terminate the TLS session the pinned
        // certificate authorities were meant to authenticate.
        .no_proxy()
        // Select rustls explicitly. Cargo unifies reqwest's feature set across
        // a whole build, so another crate enabling reqwest's native-tls feature
        // must not silently change which TLS backend this client uses.
        .use_rustls_tls()
        // One prepared request is one exchange. A transport-level retry would
        // resend a nonce the relying party's policy has already committed to
        // and would duplicate an outbound call the caller did not ask for.
        .retry(reqwest::retry::never());
    if let Some(user_agent) = &config.user_agent {
        builder = builder.user_agent(user_agent.clone());
    }
    if let Some(pem) = &config.trusted_root_certificates {
        let certificates = reqwest::Certificate::from_pem_bundle(pem).map_err(|_| {
            EvidenceClientError::configuration(
                "the pinned certificate authority bundle is not readable PEM",
            )
        })?;
        if certificates.is_empty() {
            return Err(EvidenceClientError::configuration(
                "the pinned certificate authority bundle carries no certificate",
            ));
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
        // Trust exactly what the integrator pinned. Leaving the platform store
        // enabled would mean any of its authorities could also vouch for the
        // deployment, which is the opposite of pinning.
        builder = builder.tls_built_in_root_certs(false);
    }
    builder.build().map_err(|_| {
        EvidenceClientError::configuration("the outbound client options are not usable")
    })
}

fn serialize_request(body: &EvidenceRequestBody) -> Result<Vec<u8>, EvidenceClientError> {
    serde_json::to_vec(body)
        .map_err(|_| EvidenceClientError::configuration("the request body cannot be serialized"))
}

/// Why a bounded read failed, in the terms the caller can act on.
///
/// The distinction matters most for a timeout, which is the likely failure: the
/// configured total timeout runs until the body finishes, so an answer that
/// starts and stalls elapses here rather than at connection setup. No part of the
/// underlying error text is copied into the reported failure.
fn read_failure_kind(error: &BoundedReadError) -> TransportKind {
    match error {
        BoundedReadError::ContentLengthExceeded { .. }
        | BoundedReadError::BodyTooLarge { .. }
        | BoundedReadError::LengthOverflow => TransportKind::ResponseTooLarge,
        BoundedReadError::Transport(error) if error.is_timeout() => TransportKind::Timeout,
        // The reader's error type is open, so a variant this crate does not know
        // yet becomes the coarse exchange failure. It must never become a claim
        // about the response size, which is the one thing an adopter would act on
        // by raising their own bound.
        _ => TransportKind::Exchange,
    }
}

/// Read the role-bound subject bindings out of a response that has not been
/// verified.
///
/// This is a bounded structural read of untrusted bytes, using the same strict
/// payload type the verifier uses, for one purpose only: turning the response's
/// claimed subject set into stated expectations under first-use acceptance. It
/// authenticates nothing. When the bytes are unreadable it yields no subject at
/// all, so the verifier itself refuses the response.
fn untrusted_subject_bindings(body: &[u8]) -> Vec<ExpectedSubjectDocument> {
    let Ok(jws) = serde_json::from_slice::<FlattenedJws>(body) else {
        return Vec::new();
    };
    let Ok(payload) = URL_SAFE_NO_PAD.decode(jws.payload.as_bytes()) else {
        return Vec::new();
    };
    let Ok(evidence) = serde_json::from_slice::<Evidence>(&payload) else {
        return Vec::new();
    };
    evidence
        .subjects
        .iter()
        .map(|subject: &SubjectBinding| ExpectedSubjectDocument {
            role: subject.role.clone(),
            binding: subject.binding.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures::{
            signed_evidence, SignedEvidenceFixture, AUDIENCE, CONCEPT, CONFIGURATION_REVISION,
            EVIDENCE_TYPE, ISSUED_BY, MAXIMUM_LIFETIME_SECONDS, PROVIDED_BY, PURPOSE, REQUIREMENT,
        },
        prepare::{EvidenceRequestSpec, SubjectRequest},
        request::SelectorValue,
        token::StaticToken,
    };
    use registry_evidence_verifier::{
        verifier::{
            ExpectedFormDocument, ExpectedOutputDocument, ExpectedScalarFormDocument,
            VerificationError,
        },
        AssuranceProfile,
    };
    use registry_platform_httputil::BoundedReadError;
    use std::{net::TcpListener, sync::Arc, time::Duration};
    use wiremock::{
        matchers::{any, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    /// The identifier shape the deployment publishes: a ULID.
    const OPERATION: &str = "01JQ0QZ8YHZ0000000000000AB";

    fn config_for(base_url: &str, fixture: &SignedEvidenceFixture) -> EvidenceClientConfig {
        EvidenceClientConfig::new(
            Url::parse(base_url).expect("the base URL parses"),
            Arc::new(StaticToken::new("test-token").expect("the credential is accepted")),
            fixture.trusted_jwks.clone(),
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
            expected_outputs: vec![ExpectedOutputDocument {
                concept: CONCEPT.to_owned(),
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
            operation: Some("01JZZZOPERATION".to_owned()),
        }
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
        assert_eq!(verified.operation(), Some("01JZZZOPERATION"));
        assert_eq!(verified.evidence().request_nonce, prepared.request_nonce());
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
            assert!(untrusted_subject_bindings(&body).is_empty());
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
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                fixture.sign(prepared.request_nonce()),
                EVIDENCE_JWS_MEDIA_TYPE,
            ))
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

    /// A body the problem contract does not cover leaves the client with nothing
    /// to say about the failure, which is exactly when the deployment's own
    /// identifier for the exchange matters. A header value outside the rule is
    /// still dropped rather than copied into the relying party's records.
    #[tokio::test]
    async fn a_failure_carries_the_correlation_identifier_even_with_an_unreadable_body() {
        let fixture = signed_evidence();
        for (sent, expected) in [
            (OPERATION, Some(OPERATION.to_owned())),
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
                        .insert_header(CORRELATION_HEADER, sent)
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
                    operation: expected,
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
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
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
                    .insert_header(CORRELATION_HEADER, OPERATION)
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
                operation: Some(OPERATION.to_owned()),
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
                ResponseTemplate::new(200).set_body_raw(vec![b'a'; 4096], EVIDENCE_JWS_MEDIA_TYPE),
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
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
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
        for (bundle, reason) in [
            (
                b"".to_vec(),
                "the pinned certificate authority bundle carries no certificate",
            ),
            (
                b"not a certificate".to_vec(),
                "the pinned certificate authority bundle carries no certificate",
            ),
            // The PEM framing is accepted and the content is rejected later, when
            // the outbound client is built, so this one surfaces as the coarse
            // options failure. It is still refused at construction, which is what
            // keeps the platform store from quietly taking over.
            (
                b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"
                    .to_vec(),
                "the outbound client options are not usable",
            ),
        ] {
            assert_eq!(
                EvidenceClient::new(
                    config_for("https://evidence.example.org", &fixture)
                        .with_trusted_root_certificates(bundle.clone())
                )
                .map(|_| ())
                .expect_err("unusable trust material is refused"),
                EvidenceClientError::configuration(reason),
                "{:?}",
                String::from_utf8_lossy(&bundle)
            );
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
            .respond_with(ResponseTemplate::new(200))
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
                operation: None,
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
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                fixture.sign(prepared.request_nonce()),
                EVIDENCE_JWS_MEDIA_TYPE,
            ))
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
}

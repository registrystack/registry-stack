//! Evidence-owned protocols over the shared engine's sealed data channel.
//!
//! Only this trusted host receives direct requester attribution or unverified
//! signed response bytes. Provider scripts receive verified projected values.
use std::sync::Arc;

use http::{header, HeaderName, HeaderValue};
use registry_adapter_core::{ComponentKind, Endpoint, EndpointAuthentication, HttpMethod};
use registry_adapter_engine::host_protocol::{
    CompiledHostProtocol, ExactProblemClassifier, HostAccessAttribution, HostProtocolCompiler,
    HostProtocolError, HostProtocolMethod, HostProtocolRegistry, HostProtocolRequestContext,
    HostProtocolResponseRefusal, HostProtocolResponseVerifier, HostProtocolWireResponse,
    PreparedHostProtocolRequest, VerifiedHostProtocolResponse,
};
use registry_evidence_client::RetainedEvidenceVerification;
use zeroize::Zeroizing;

use crate::{source::SourceAccessAttribution, source_evidence::EvidenceSourceConfig};

/// The closed built-in protocol registry used for both pure checks and live
/// source execution. Ordinary endpoints select no protocol.
pub fn registry() -> Result<HostProtocolRegistry, HostProtocolError> {
    #[allow(unused_mut, reason = "optional protocols are appended by feature")]
    let mut compilers = vec![
        Arc::new(SignedEvidenceCompiler) as Arc<dyn HostProtocolCompiler>,
        Arc::new(AttributionCompiler) as Arc<dyn HostProtocolCompiler>,
        Arc::new(LookupCompiler) as Arc<dyn HostProtocolCompiler>,
    ];
    #[cfg(feature = "wallet-presentation")]
    compilers.push(Arc::new(
        crate::wallet_presentation::WalletPresentationCompiler,
    ));
    HostProtocolRegistry::try_new(compilers)
}

static SIGNED_REQUEST_HEADERS: [HeaderName; 1] = [header::ACCEPT];
static ATTRIBUTION_REQUEST_HEADERS: [HeaderName; 2] = [
    HeaderName::from_static("registry-access-requester"),
    HeaderName::from_static("registry-access-purpose"),
];

struct SignedEvidenceCompiler;
impl HostProtocolCompiler for SignedEvidenceCompiler {
    fn id(&self) -> &str {
        "signed-evidence-v1"
    }

    fn compile(
        &self,
        endpoint: &Endpoint,
        config: &[u8],
    ) -> Result<Arc<dyn CompiledHostProtocol>, HostProtocolError> {
        require_http(endpoint)?;
        if matches!(&endpoint.authentication, EndpointAuthentication::None {}) {
            return Err(HostProtocolError);
        }
        let config: EvidenceSourceConfig =
            serde_json::from_slice(config).map_err(|_| HostProtocolError)?;
        config.validate_contract().map_err(|_| HostProtocolError)?;
        Ok(Arc::new(SignedEvidenceProtocol {
            config: Arc::new(config),
            response_headers: vec![header::CONTENT_TYPE, HeaderName::from_static("traceparent")],
        }))
    }
}

struct SignedEvidenceProtocol {
    config: Arc<EvidenceSourceConfig>,
    response_headers: Vec<HeaderName>,
}
impl CompiledHostProtocol for SignedEvidenceProtocol {
    fn request_header_names(&self) -> &[HeaderName] {
        &SIGNED_REQUEST_HEADERS
    }

    fn response_header_names(&self) -> &[HeaderName] {
        &self.response_headers
    }

    fn allows_credential_refresh_retry(&self) -> bool {
        true
    }

    fn prepare_attempt(
        &self,
        request: HostProtocolRequestContext<'_>,
        _attribution: Option<&HostAccessAttribution>,
        maximum_request_bytes: usize,
    ) -> Result<PreparedHostProtocolRequest, HostProtocolError> {
        let method = match request.method() {
            HostProtocolMethod::Get => HttpMethod::Get,
            HostProtocolMethod::Post => HttpMethod::Post,
        };
        EvidenceSourceConfig::validate_request_shape(method, request.path(), request.has_query())
            .map_err(|_| HostProtocolError)?;
        self.config
            .validate_subjects(request.body())
            .map_err(|_| HostProtocolError)?;
        let (body, verification) = self
            .config
            .prepare(request.body(), maximum_request_bytes)
            .map_err(|_| HostProtocolError)?;
        Ok(PreparedHostProtocolRequest::new(
            Zeroizing::new(body),
            vec![(
                header::ACCEPT,
                HeaderValue::from_static(crate::EVIDENCE_JWS_MEDIA_TYPE),
            )],
            Box::new(SignedEvidenceVerifier {
                config: Arc::clone(&self.config),
                verification,
            }),
        ))
    }
}

struct SignedEvidenceVerifier {
    config: Arc<EvidenceSourceConfig>,
    verification: RetainedEvidenceVerification,
}
impl HostProtocolResponseVerifier for SignedEvidenceVerifier {
    fn verify(
        self: Box<Self>,
        response: HostProtocolWireResponse,
    ) -> Result<VerifiedHostProtocolResponse, HostProtocolResponseRefusal> {
        let mut trusted_headers = http::HeaderMap::new();
        for (name, value) in response.headers() {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| HostProtocolResponseRefusal::Protocol)?;
            let value =
                HeaderValue::from_str(value).map_err(|_| HostProtocolResponseRefusal::Protocol)?;
            trusted_headers.append(name, value);
        }
        registry_platform_httpsec::response_trace_id(&trusted_headers)
            .map_err(|_| HostProtocolResponseRefusal::Verification)?;
        let mut media_types = response
            .headers()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        let media_type = media_types.next().map(|(_, value)| value.as_str());
        if response.status() != 200
            || media_types.next().is_some()
            || !media_type.is_some_and(|value| {
                value.split(';').next().is_some_and(|media| {
                    media
                        .trim()
                        .eq_ignore_ascii_case(crate::EVIDENCE_JWS_MEDIA_TYPE)
                })
            })
        {
            return Err(HostProtocolResponseRefusal::Protocol);
        }
        // An upstream assertion is issued after this request was sent, so it is
        // judged at the instant its response is verified. The acquisition's
        // evaluation instant is earlier and would refuse an assertion issued in
        // a later whole second as issued in the future.
        let (values, valid_until) = self
            .config
            .verified_values(
                &self.verification,
                &response.into_body(),
                chrono::Utc::now(),
            )
            .map_err(|_| HostProtocolResponseRefusal::Verification)?;
        Ok(VerifiedHostProtocolResponse::new(
            values,
            Some(valid_until.to_rfc3339()),
        ))
    }
}

struct AttributionCompiler;
impl HostProtocolCompiler for AttributionCompiler {
    fn id(&self) -> &str {
        "access-attribution-v1"
    }

    fn compile(
        &self,
        endpoint: &Endpoint,
        config: &[u8],
    ) -> Result<Arc<dyn CompiledHostProtocol>, HostProtocolError> {
        require_http(endpoint)?;
        let config: serde_json::Value =
            serde_json::from_slice(config).map_err(|_| HostProtocolError)?;
        if !config.as_object().is_some_and(serde_json::Map::is_empty) {
            return Err(HostProtocolError);
        }
        Ok(Arc::new(AttributionProtocol))
    }
}
struct AttributionProtocol;
impl CompiledHostProtocol for AttributionProtocol {
    fn request_header_names(&self) -> &[HeaderName] {
        &ATTRIBUTION_REQUEST_HEADERS
    }

    fn requires_access_attribution(&self) -> bool {
        true
    }

    fn response_header_names(&self) -> &[HeaderName] {
        &[]
    }

    fn allows_credential_refresh_retry(&self) -> bool {
        true
    }

    fn prepare_attempt(
        &self,
        _request: HostProtocolRequestContext<'_>,
        attribution: Option<&HostAccessAttribution>,
        _maximum_request_bytes: usize,
    ) -> Result<PreparedHostProtocolRequest, HostProtocolError> {
        let attribution = attribution.ok_or(HostProtocolError)?;
        let (requester, purpose) =
            SourceAccessAttribution::new(attribution.requester(), attribution.purpose())
                .headers()
                .map_err(|_| HostProtocolError)?;
        Ok(PreparedHostProtocolRequest::passthrough(vec![
            (
                HeaderName::from_static("registry-access-requester"),
                requester,
            ),
            (HeaderName::from_static("registry-access-purpose"), purpose),
        ]))
    }
}

/// The source's reviewed exact lookup Problem contract. Its raw body stays
/// inside the trusted protocol verifier, even when access logging is disabled.
struct LookupCompiler;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LookupConfig {
    unresolved_problem: serde_json::Value,
    forward_access_attribution: bool,
}

impl HostProtocolCompiler for LookupCompiler {
    fn id(&self) -> &str {
        "registry-lookup-v1"
    }

    fn compile(
        &self,
        endpoint: &Endpoint,
        config: &[u8],
    ) -> Result<Arc<dyn CompiledHostProtocol>, HostProtocolError> {
        require_http(endpoint)?;
        let value = registry_platform_httputil::destination::json::decode_protocol_json(
            Zeroizing::new(config.to_vec()),
        )
        .map_err(|_| HostProtocolError)?
        .into_parts()
        .0;
        let config: LookupConfig = serde_json::from_value(value).map_err(|_| HostProtocolError)?;
        let classifier = ExactProblemClassifier::from_config(
            &serde_json::to_vec(&config.unresolved_problem).map_err(|_| HostProtocolError)?,
        )?;
        Ok(Arc::new(LookupProtocol {
            classifier: Arc::new(classifier),
            forward_access_attribution: config.forward_access_attribution,
        }))
    }
}

struct LookupProtocol {
    classifier: Arc<ExactProblemClassifier>,
    forward_access_attribution: bool,
}

impl CompiledHostProtocol for LookupProtocol {
    fn request_header_names(&self) -> &[HeaderName] {
        if self.forward_access_attribution {
            &ATTRIBUTION_REQUEST_HEADERS
        } else {
            &[]
        }
    }

    fn response_header_names(&self) -> &[HeaderName] {
        static HEADERS: [HeaderName; 1] = [header::CONTENT_TYPE];
        &HEADERS
    }

    fn requires_access_attribution(&self) -> bool {
        self.forward_access_attribution
    }

    fn allows_credential_refresh_retry(&self) -> bool {
        true
    }

    /// The lookup verifier classifies a JSON Problem by its members and signs
    /// nothing, so a fixture may record the response as a readable `body`.
    fn replays_readable_body(&self) -> bool {
        true
    }

    fn prepare_attempt(
        &self,
        _request: HostProtocolRequestContext<'_>,
        attribution: Option<&HostAccessAttribution>,
        _maximum_request_bytes: usize,
    ) -> Result<PreparedHostProtocolRequest, HostProtocolError> {
        let headers = if self.forward_access_attribution {
            let attribution = attribution.ok_or(HostProtocolError)?;
            let (requester, purpose) =
                SourceAccessAttribution::new(attribution.requester(), attribution.purpose())
                    .headers()
                    .map_err(|_| HostProtocolError)?;
            vec![
                (ATTRIBUTION_REQUEST_HEADERS[0].clone(), requester),
                (ATTRIBUTION_REQUEST_HEADERS[1].clone(), purpose),
            ]
        } else {
            Vec::new()
        };
        Ok(PreparedHostProtocolRequest::verified_passthrough(
            headers,
            Box::new(LookupVerifier {
                classifier: Arc::clone(&self.classifier),
            }),
        ))
    }
}

struct LookupVerifier {
    classifier: Arc<ExactProblemClassifier>,
}

impl HostProtocolResponseVerifier for LookupVerifier {
    fn verify(
        self: Box<Self>,
        response: HostProtocolWireResponse,
    ) -> Result<VerifiedHostProtocolResponse, HostProtocolResponseRefusal> {
        let status = response.status();
        let classified = self.classifier.classify(&response).map_err(|_| {
            if status == 404 {
                HostProtocolResponseRefusal::DeclaredNotFoundMismatch
            } else {
                HostProtocolResponseRefusal::Protocol
            }
        })?;
        if classified {
            return Ok(VerifiedHostProtocolResponse::new(
                serde_json::json!({"lookup":"unresolved"}),
                None,
            )
            .without_response_headers());
        }
        let mut media_types = response
            .headers()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        let media_type = media_types.next().map(|(_, value)| value.as_str());
        if !(200..300).contains(&response.status())
            || media_types.next().is_some()
            || !media_type.is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
            })
        {
            return Err(HostProtocolResponseRefusal::Protocol);
        }
        let (body, _) = registry_platform_httputil::destination::json::decode_protocol_json(
            response.into_body(),
        )
        .map_err(|_| HostProtocolResponseRefusal::Protocol)?
        .into_parts();
        Ok(VerifiedHostProtocolResponse::new(body, None))
    }
}

fn require_http(endpoint: &Endpoint) -> Result<(), HostProtocolError> {
    if endpoint.component == ComponentKind::Http {
        Ok(())
    } else {
        Err(HostProtocolError)
    }
}

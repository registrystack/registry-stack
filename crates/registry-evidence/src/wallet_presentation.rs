//! The wallet presentation host protocol, `wallet-presentation-v1`.
//!
//! A sibling of `signed-evidence-v1` for a credential a holder presented from a
//! wallet. The route sends a closed request naming a session reference and the
//! presenting principal to the wallet protocol service. The response carries
//! the presentation and the session context the service created. This module
//! verifies the presentation in Evidence with the pure
//! `registry-evidence-presentation` crate and hands the route a closed
//! projection of the declared claims, plus a trusted [`PresentedFacts`]
//! attachment that only assertion construction reads.
//!
//! The protocol service is relied on for the context it created. It is never
//! relied on for a credential's authenticity: issuer trust, element integrity
//! and holder binding are decided here.
use std::{collections::BTreeMap, collections::BTreeSet, sync::Arc};

use chrono::{DateTime, Utc};
use http::{header, HeaderName, HeaderValue};
use registry_adapter_core::{Endpoint, EndpointAuthentication};
use registry_adapter_engine::host_protocol::{
    CompiledHostProtocol, HostAccessAttribution, HostProtocolCompiler, HostProtocolError,
    HostProtocolMethod, HostProtocolRequestContext, HostProtocolResponseRefusal,
    HostProtocolResponseVerifier, HostProtocolWireResponse, PreparedHostProtocolRequest,
    VerifiedHostProtocolResponse,
};
use registry_evidence_presentation::{
    verify_sd_jwt_vc, ChannelPolicy, IssuerDenyList, IssuerDenyListConfig, IssuerTrust,
    SessionContext, TrustConfigError, TrustEntryConfig,
};
use registry_platform_crypto::parse_json_strict;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    config::WALLET_PRESENTATION_PROTOCOL_ID as WALLET_PRESENTATION_PROTOCOL,
    model::{PresentedCredential, SubjectLinkMode},
    presented::PresentedFacts,
};

/// The only path the protocol reads: the wallet protocol service's read
/// endpoint.
const READ_PATH: &str = "/v1/presentations/read";
const JSON_MEDIA_TYPE: &str = "application/json";
const MAXIMUM_TEXT_BYTES: usize = 512;
const MAXIMUM_CLAIMS: usize = 64;
const MAXIMUM_CLAIM_NAME_BYTES: usize = 128;
/// Ten years of 365 days, the verifier's cap. The age is measured from `iat`,
/// so a long-lived identity credential needs a long cap; a deployment that
/// wants freshness configures a smaller value.
const MAXIMUM_CREDENTIAL_AGE_SECONDS: u32 = 315_360_000;
/// The largest time the OpenID4VP verifier service holds a result: the upper
/// bound of its profile's `result_ttl_seconds`. A presentation received longer
/// ago than this, beyond clock skew, cannot still be held.
const MAXIMUM_RESULT_WINDOW_SECONDS: i64 = 3_600;

/// Claims whose values the protocol never projects: protocol-reserved members
/// and the members the closed `verification` object already states.
const RESERVED_CLAIMS: [&str; 11] = [
    "iss",
    "vct",
    "iat",
    "nbf",
    "exp",
    "cnf",
    "status",
    "_sd",
    "_sd_alg",
    "verification",
    "values",
];

static REQUEST_HEADERS: [HeaderName; 1] = [header::ACCEPT];
static RESPONSE_HEADERS: [HeaderName; 2] =
    [header::CONTENT_TYPE, HeaderName::from_static("traceparent")];

/// Why a channel configuration was refused. Every message is fixed text; none
/// carries a configured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum WalletConfigError {
    #[error("the configuration is not a closed wallet-presentation-v1 document")]
    Malformed,
    #[error("an identifier is empty, too long or holds a control character")]
    Identifier,
    #[error("status checking is not available; declare status as not-checked")]
    StatusCheckingUnavailable,
    #[error("holder binding is always performed; keyBindingRequired must be true")]
    KeyBindingNotRequired,
    #[error("the channel policy accepts no credential type")]
    NoCredentialType,
    #[error("maximumCredentialAgeSeconds must be between 1 and 315360000")]
    MaximumCredentialAge,
    #[error("disclosedClaims is too long, repeats a name or names a reserved claim")]
    DisclosedClaims,
    #[error("subjectLink attribute-match needs at least one disclosed claim to compare")]
    AttributeMatchWithoutClaims,
    #[error("a trust entry id is not a local identifier")]
    TrustEntryId,
    #[error("the issuer trust configuration is unusable")]
    Trust(TrustConfigError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StatusMode {
    Required,
    NotChecked,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawConfig {
    policy_id: String,
    client_id: String,
    credential_query_id: String,
    trust: Vec<TrustEntryConfig>,
    deny: IssuerDenyListConfig,
    policy: ChannelPolicy,
    disclosed_claims: Vec<String>,
    status: StatusMode,
    maximum_credential_age_seconds: u32,
    subject_link: SubjectLinkMode,
}

/// A validated channel configuration.
pub(crate) struct WalletPresentationConfig {
    policy_id: String,
    client_id: String,
    credential_query_id: String,
    trust: IssuerTrust,
    policy: ChannelPolicy,
    disclosed_claims: Vec<String>,
    maximum_credential_age_seconds: u32,
    subject_link: SubjectLinkMode,
}

impl WalletPresentationConfig {
    /// Parse and validate the digest-pinned configuration bytes.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, WalletConfigError> {
        let value = parse_json_strict(bytes).map_err(|_| WalletConfigError::Malformed)?;
        let raw: RawConfig =
            serde_json::from_value(value).map_err(|_| WalletConfigError::Malformed)?;
        for text in [&raw.policy_id, &raw.client_id, &raw.credential_query_id] {
            require_text(text)?;
        }
        match raw.status {
            StatusMode::Required => return Err(WalletConfigError::StatusCheckingUnavailable),
            StatusMode::NotChecked => {}
        }
        if !raw.policy.key_binding_required {
            return Err(WalletConfigError::KeyBindingNotRequired);
        }
        if raw.policy.vct.is_empty() || raw.policy.vct.iter().any(String::is_empty) {
            return Err(WalletConfigError::NoCredentialType);
        }
        if !(1..=MAXIMUM_CREDENTIAL_AGE_SECONDS).contains(&raw.maximum_credential_age_seconds) {
            return Err(WalletConfigError::MaximumCredentialAge);
        }
        validate_disclosed_claims(&raw.disclosed_claims)?;
        // A link labelled attribute-match states that disclosed claims were
        // compared with the expected record; with none disclosed, nothing was.
        if raw.subject_link == SubjectLinkMode::AttributeMatch && raw.disclosed_claims.is_empty() {
            return Err(WalletConfigError::AttributeMatchWithoutClaims);
        }
        for entry in &raw.trust {
            // A matched entry is stated in an assertion, so its id must meet
            // the assertion contract.
            PresentedCredential::new(
                &entry.id,
                "https://issuer.invalid",
                "credential-type",
                DateTime::<Utc>::UNIX_EPOCH,
                raw.subject_link,
            )
            .map_err(|_| WalletConfigError::TrustEntryId)?;
        }
        let deny = IssuerDenyList::try_from(raw.deny).map_err(WalletConfigError::Trust)?;
        let trust = IssuerTrust::try_from(raw.trust)
            .map_err(WalletConfigError::Trust)?
            .with_deny_list(deny);
        Ok(Self {
            policy_id: raw.policy_id,
            client_id: raw.client_id,
            credential_query_id: raw.credential_query_id,
            trust,
            policy: raw.policy,
            disclosed_claims: raw.disclosed_claims,
            maximum_credential_age_seconds: raw.maximum_credential_age_seconds,
            subject_link: raw.subject_link,
        })
    }
}

fn require_text(text: &str) -> Result<(), WalletConfigError> {
    if text.is_empty() || text.len() > MAXIMUM_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(WalletConfigError::Identifier);
    }
    Ok(())
}

fn validate_disclosed_claims(claims: &[String]) -> Result<(), WalletConfigError> {
    let distinct = claims.iter().collect::<BTreeSet<_>>();
    let valid = claims.len() <= MAXIMUM_CLAIMS
        && distinct.len() == claims.len()
        && claims.iter().all(|name| {
            !name.is_empty()
                && name.len() <= MAXIMUM_CLAIM_NAME_BYTES
                && !name.chars().any(char::is_control)
                && !RESERVED_CLAIMS.contains(&name.as_str())
        });
    if valid {
        Ok(())
    } else {
        Err(WalletConfigError::DisclosedClaims)
    }
}

pub(crate) struct WalletPresentationCompiler;

impl HostProtocolCompiler for WalletPresentationCompiler {
    fn id(&self) -> &str {
        WALLET_PRESENTATION_PROTOCOL
    }

    fn compile(
        &self,
        endpoint: &Endpoint,
        config: &[u8],
    ) -> Result<Arc<dyn CompiledHostProtocol>, HostProtocolError> {
        if endpoint.component != registry_adapter_core::ComponentKind::Http {
            return Err(HostProtocolError);
        }
        if matches!(&endpoint.authentication, EndpointAuthentication::None {}) {
            tracing::warn!(
                protocol = WALLET_PRESENTATION_PROTOCOL,
                "the protocol refuses an endpoint with no authentication"
            );
            return Err(HostProtocolError);
        }
        let config = WalletPresentationConfig::parse(config).map_err(|error| {
            tracing::warn!(
                protocol = WALLET_PRESENTATION_PROTOCOL,
                %error,
                "the protocol configuration was refused"
            );
            HostProtocolError
        })?;
        Ok(Arc::new(WalletPresentationProtocol {
            config: Arc::new(config),
        }))
    }
}

struct WalletPresentationProtocol {
    config: Arc<WalletPresentationConfig>,
}

/// The only body the protocol sends, forwarded unchanged.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    reference: String,
    principal: Principal,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Principal {
    issuer: String,
    subject: String,
}

impl ReadRequest {
    fn from_body(body: &Value) -> Option<Self> {
        let request = Self::deserialize(body).ok()?;
        let bounded = [
            &request.reference,
            &request.principal.issuer,
            &request.principal.subject,
        ]
        .into_iter()
        .all(|text| require_text(text).is_ok());
        bounded.then_some(request)
    }
}

impl CompiledHostProtocol for WalletPresentationProtocol {
    fn request_header_names(&self) -> &[HeaderName] {
        &REQUEST_HEADERS
    }

    fn response_header_names(&self) -> &[HeaderName] {
        &RESPONSE_HEADERS
    }

    fn allows_credential_refresh_retry(&self) -> bool {
        true
    }

    fn prepare_attempt(
        &self,
        request: HostProtocolRequestContext<'_>,
        _attribution: Option<&HostAccessAttribution>,
        _maximum_request_bytes: usize,
    ) -> Result<PreparedHostProtocolRequest, HostProtocolError> {
        if request.method() != HostProtocolMethod::Post
            || request.path() != READ_PATH
            || request.has_query()
        {
            return Err(HostProtocolError);
        }
        let read = request
            .body()
            .and_then(ReadRequest::from_body)
            .ok_or(HostProtocolError)?;
        Ok(PreparedHostProtocolRequest::verified_passthrough(
            vec![(header::ACCEPT, HeaderValue::from_static(JSON_MEDIA_TYPE))],
            Box::new(WalletPresentationVerifier {
                config: Arc::clone(&self.config),
                principal: read.principal,
            }),
        ))
    }
}

/// The wallet protocol service's read response, mirrored as a closed type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadResponse {
    presentation: BTreeMap<String, Vec<String>>,
    context: ReadContext,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadContext {
    nonce: String,
    client_id: String,
    // The service states these members; Evidence reads none of them.
    #[serde(rename = "responseUri")]
    _response_uri: String,
    #[serde(rename = "responseKeyThumbprint")]
    _response_key_thumbprint: String,
    policy_id: String,
    created_by: Principal,
    received_at: String,
}

impl Drop for ReadResponse {
    fn drop(&mut self) {
        for presentation in std::mem::take(&mut self.presentation).into_values() {
            presentation.into_iter().for_each(|mut text| text.zeroize());
        }
        self.context.nonce.zeroize();
    }
}

struct WalletPresentationVerifier {
    config: Arc<WalletPresentationConfig>,
    principal: Principal,
}

impl HostProtocolResponseVerifier for WalletPresentationVerifier {
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
                value
                    .split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case(JSON_MEDIA_TYPE))
            })
        {
            return Err(HostProtocolResponseRefusal::Protocol);
        }
        let evaluation_instant = response.evaluation_instant();
        let body = response.into_body();
        let read = parse_json_strict(&body)
            .ok()
            .and_then(|value| serde_json::from_value::<ReadResponse>(value).ok())
            .ok_or(HostProtocolResponseRefusal::Protocol)?;
        drop(body);
        self.verified(&read, evaluation_instant)
    }
}

impl WalletPresentationVerifier {
    fn verified(
        &self,
        read: &ReadResponse,
        now: DateTime<Utc>,
    ) -> Result<VerifiedHostProtocolResponse, HostProtocolResponseRefusal> {
        let config = &*self.config;
        let context = &read.context;
        if context.policy_id != config.policy_id
            || context.client_id != config.client_id
            || context.created_by != self.principal
        {
            return Err(HostProtocolResponseRefusal::Verification);
        }
        // Exactly the configured query, answered by exactly one credential.
        let presented = match (
            read.presentation.len(),
            read.presentation.get(&config.credential_query_id),
        ) {
            (1, Some(presented)) => presented,
            _ => return Err(HostProtocolResponseRefusal::Protocol),
        };
        let [presentation] = presented.as_slice() else {
            return Err(HostProtocolResponseRefusal::Protocol);
        };
        let received_at = DateTime::parse_from_rfc3339(&context.received_at)
            .map_err(|_| HostProtocolResponseRefusal::Protocol)?
            .timestamp();
        if !received_within_window(
            received_at,
            now.timestamp(),
            i64::from(config.policy.clock_skew_seconds),
        ) {
            return Err(HostProtocolResponseRefusal::Verification);
        }
        let session = SessionContext {
            nonce: context.nonce.clone(),
            client_id: context.client_id.clone(),
            received_at,
        };
        let now_seconds = now.timestamp();
        let credential = verify_sd_jwt_vc(
            presentation,
            &session,
            &config.trust,
            &config.policy,
            now_seconds,
        )
        .map_err(|refusal| {
            tracing::debug!(%refusal, "the wallet presentation was refused");
            HostProtocolResponseRefusal::Verification
        })?;
        if !credential.key_bound {
            return Err(HostProtocolResponseRefusal::Verification);
        }
        let age_bound = credential
            .issued_at
            .saturating_add(i64::from(config.maximum_credential_age_seconds));
        let expires_at = credential
            .expires_at
            .map_or(age_bound, |expiry| expiry.min(age_bound));
        // A credential at or past the age bound, or inside the verifier's
        // clock-skew tolerance of its own expiry, has no validity left to give
        // an assertion.
        if expires_at <= now_seconds {
            return Err(HostProtocolResponseRefusal::Verification);
        }
        let issued_at = instant(credential.issued_at)?;
        let expires_at = instant(expires_at)?;
        let presented_credential = PresentedCredential::new(
            credential.trust_entry.as_str(),
            credential.issuer.as_str(),
            credential.vct.as_str(),
            issued_at,
            config.subject_link,
        )
        .map_err(|_| HostProtocolResponseRefusal::Verification)?;

        let mut values = Map::new();
        for name in &config.disclosed_claims {
            if let Some(value) = credential.claims.get(name) {
                values.insert(name.clone(), value.clone());
            }
        }
        let body = json!({
            "lookup": "matched",
            "values": values,
            "verification": {
                "trustEntry": credential.trust_entry,
                "credentialType": credential.vct,
                "issuedAt": issued_at.to_rfc3339(),
            },
        });
        Ok(
            VerifiedHostProtocolResponse::new(body, Some(expires_at.to_rfc3339()))
                .without_response_headers()
                .with_attachment(Arc::new(PresentedFacts::new(
                    presented_credential,
                    expires_at,
                ))),
        )
    }
}

/// Whether a presentation's receipt time is plausible for the read happening
/// at `now`: not later than `now` plus the skew, and not earlier than `now`
/// less the largest result window and the skew. The verifier service states
/// the receipt time, so a compromised one could otherwise replay a
/// presentation it kept long after it arrived.
fn received_within_window(received_at: i64, now: i64, skew_seconds: i64) -> bool {
    received_at <= now.saturating_add(skew_seconds)
        && received_at >= now.saturating_sub(MAXIMUM_RESULT_WINDOW_SECONDS + skew_seconds)
}

fn instant(seconds: i64) -> Result<DateTime<Utc>, HostProtocolResponseRefusal> {
    DateTime::from_timestamp(seconds, 0).ok_or(HostProtocolResponseRefusal::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwks_entry(id: &str) -> Value {
        json!({
            "id": id, "issuer": "https://issuer.example", "vct": ["urn:vct:income"],
            "keys": {"jwks": [{
                "kty": "OKP", "crv": "Ed25519", "kid": "k1",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }]}
        })
    }

    fn config() -> Value {
        json!({
            "policyId": "income-check",
            "clientId": "x509_san_dns:verifier.example",
            "credentialQueryId": "income",
            "trust": [jwks_entry("agency-a")],
            "deny": {"issuers": [], "certificateSha256": []},
            "policy": {"vct": ["urn:vct:income"], "keyBindingRequired": true},
            "disclosedClaims": ["family_name"],
            "status": "not-checked",
            "maximumCredentialAgeSeconds": 86400,
            "subjectLink": "possession"
        })
    }

    fn parse(value: &Value) -> Result<WalletPresentationConfig, WalletConfigError> {
        WalletPresentationConfig::parse(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn a_complete_configuration_is_accepted() {
        assert!(parse(&config()).is_ok());
    }

    #[test]
    fn status_required_is_refused_with_a_message_that_says_why() {
        let mut value = config();
        value["status"] = json!("required");
        let error = parse(&value).err().unwrap();
        assert_eq!(error, WalletConfigError::StatusCheckingUnavailable);
        assert!(error
            .to_string()
            .contains("status checking is not available"));
    }

    #[test]
    fn holder_binding_is_always_required() {
        let mut value = config();
        value["policy"]["keyBindingRequired"] = json!(false);
        assert_eq!(
            parse(&value).err(),
            Some(WalletConfigError::KeyBindingNotRequired)
        );
    }

    #[test]
    fn every_member_is_required_and_unknown_members_are_refused() {
        for member in [
            "policyId",
            "clientId",
            "credentialQueryId",
            "trust",
            "deny",
            "policy",
            "disclosedClaims",
            "status",
            "maximumCredentialAgeSeconds",
            "subjectLink",
        ] {
            let mut value = config();
            value.as_object_mut().unwrap().remove(member);
            assert_eq!(
                parse(&value).err(),
                Some(WalletConfigError::Malformed),
                "{member} is required"
            );
        }
        let mut value = config();
        value["extra"] = json!(true);
        assert_eq!(parse(&value).err(), Some(WalletConfigError::Malformed));
        let mut value = config();
        value["deny"] = json!({"issuers": []});
        assert_eq!(parse(&value).err(), Some(WalletConfigError::Malformed));
    }

    #[test]
    fn duplicate_members_and_non_json_are_refused() {
        assert_eq!(
            WalletPresentationConfig::parse(b"{\"policyId\":\"a\",\"policyId\":\"b\"}").err(),
            Some(WalletConfigError::Malformed)
        );
        assert_eq!(
            WalletPresentationConfig::parse(b"not json").err(),
            Some(WalletConfigError::Malformed)
        );
    }

    #[test]
    fn the_credential_age_is_bounded() {
        for seconds in [0_u64, 315_360_001, u64::from(u32::MAX) + 1] {
            let mut value = config();
            value["maximumCredentialAgeSeconds"] = json!(seconds);
            assert!(parse(&value).is_err(), "{seconds}");
        }
        for seconds in [1, 31_536_001, 315_360_000] {
            let mut value = config();
            value["maximumCredentialAgeSeconds"] = json!(seconds);
            assert!(parse(&value).is_ok(), "{seconds}");
        }
    }

    #[test]
    fn disclosed_claims_are_a_closed_distinct_unreserved_list() {
        for claims in [
            json!(["a", "a"]),
            json!(["cnf"]),
            json!(["verification"]),
            json!([""]),
        ] {
            let mut value = config();
            value["disclosedClaims"] = claims;
            assert_eq!(
                parse(&value).err(),
                Some(WalletConfigError::DisclosedClaims)
            );
        }
    }

    #[test]
    fn an_empty_disclosed_claims_list_projects_nothing_and_is_accepted() {
        let mut value = config();
        value["disclosedClaims"] = json!([]);
        assert!(parse(&value).is_ok());
    }

    #[test]
    fn attribute_match_with_no_disclosed_claim_is_refused() {
        let mut value = config();
        value["subjectLink"] = json!("attribute-match");
        value["disclosedClaims"] = json!([]);
        let error = parse(&value).err().unwrap();
        assert_eq!(error, WalletConfigError::AttributeMatchWithoutClaims);
        assert!(error.to_string().contains("attribute-match"));
        value["disclosedClaims"] = json!(["family_name"]);
        assert!(parse(&value).is_ok());
    }

    #[test]
    fn the_receipt_time_window_has_exact_edges() {
        let (now, skew) = (1_000_000, 60);
        let oldest = now - MAXIMUM_RESULT_WINDOW_SECONDS - skew;
        let newest = now + skew;
        assert!(received_within_window(oldest, now, skew));
        assert!(!received_within_window(oldest - 1, now, skew));
        assert!(received_within_window(newest, now, skew));
        assert!(!received_within_window(newest + 1, now, skew));
        assert!(received_within_window(now, now, 0));
        assert!(!received_within_window(now + 1, now, 0));
        assert!(!received_within_window(i64::MIN, now, skew));
        assert!(!received_within_window(i64::MAX, now, skew));
    }

    #[test]
    fn a_trust_entry_id_must_meet_the_assertion_contract() {
        let mut value = config();
        value["trust"] = json!([jwks_entry("Agency A")]);
        assert_eq!(parse(&value).err(), Some(WalletConfigError::TrustEntryId));
    }

    #[test]
    fn an_empty_credential_type_list_accepts_nothing_and_is_refused() {
        let mut value = config();
        value["policy"]["vct"] = json!([]);
        assert_eq!(
            parse(&value).err(),
            Some(WalletConfigError::NoCredentialType)
        );
    }

    #[test]
    fn the_request_body_is_exactly_a_reference_and_a_principal() {
        let good = json!({"reference": "r-1", "principal": {"issuer": "i", "subject": "s"}});
        assert!(ReadRequest::from_body(&good).is_some());
        for bad in [
            json!({"reference": "r-1"}),
            json!({"principal": {"issuer": "i", "subject": "s"}}),
            json!({"reference": "r-1", "principal": {"issuer": "i", "subject": "s"}, "x": 1}),
            json!({"reference": "r-1", "principal": {"issuer": "i", "subject": "s", "x": 1}}),
            json!({"reference": "", "principal": {"issuer": "i", "subject": "s"}}),
            json!({"reference": 7, "principal": {"issuer": "i", "subject": "s"}}),
            json!({"reference": "r\n1", "principal": {"issuer": "i", "subject": "s"}}),
            json!({"reference": "r".repeat(513), "principal": {"issuer": "i", "subject": "s"}}),
        ] {
            assert!(ReadRequest::from_body(&bad).is_none(), "{bad}");
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Explicit SD-JWT VC verification helpers.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use flate2::read::ZlibDecoder;
use registry_notary_core::SD_JWT_VC_JWT_TYP;
use registry_platform_crypto::{verify, PublicJwk, SigningAlgorithm};
use registry_platform_httputil::{read_bounded, BoundedReadError, FetchUrlError, FetchUrlPolicy};
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE};
use reqwest::{StatusCode, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

const STATUS_LIST_MEDIA_TYPE: &str = "application/statuslist+jwt";
const STATUS_LIST_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const STATUS_LIST_DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_STATUS_LIST_RESPONSE_BYTES: u64 = 256 * 1024;
const MAX_STATUS_LIST_COMPRESSED_BYTES: usize = 128 * 1024;
const MAX_STATUS_LIST_DECOMPRESSED_BYTES: usize = 128 * 1024;
const MAX_STATUS_LIST_URI_BYTES: usize = 4_096;
const MAX_STATUS_LIST_ORIGINS: usize = 16;
const MAX_STATUS_LIST_TOKEN_LIFETIME_SECONDS: i64 = 300;
const MAX_STATUS_LIST_CLOCK_SKEW_SECONDS: u64 = 60;

/// Trusted status-list origins associated with exactly one credential issuer.
///
/// The primary origin is required. Additional origins are accepted only after
/// the caller adds each exact HTTPS origin explicitly. Paths, queries,
/// fragments, URL credentials, localhost, private networks, and unsafe DNS
/// answers are still rejected by the fetch path.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusListPolicy {
    issuer: String,
    origins: BTreeSet<String>,
    #[cfg(any(test, feature = "test-support"))]
    allow_loopback_http: bool,
}

impl fmt::Debug for StatusListPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusListPolicy")
            .field("issuer", &"<redacted>")
            .field("trusted_origin_count", &self.origins.len())
            .finish()
    }
}

impl StatusListPolicy {
    /// Bind an issuer to its primary trusted HTTPS status origin.
    pub fn new(
        issuer: impl Into<String>,
        trusted_origin: impl AsRef<str>,
    ) -> Result<Self, StatusListPolicyError> {
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(StatusListPolicyError::InvalidIssuer);
        }
        let origin = parse_status_origin(trusted_origin.as_ref(), false)?;
        Ok(Self {
            issuer,
            origins: BTreeSet::from([origin]),
            #[cfg(any(test, feature = "test-support"))]
            allow_loopback_http: false,
        })
    }

    /// Add one exact HTTPS origin that is trusted for the same issuer.
    pub fn allow_origin(mut self, origin: impl AsRef<str>) -> Result<Self, StatusListPolicyError> {
        if self.origins.len() >= MAX_STATUS_LIST_ORIGINS {
            return Err(StatusListPolicyError::TooManyOrigins);
        }
        let origin = parse_status_origin(origin.as_ref(), false)?;
        self.origins.insert(origin);
        Ok(self)
    }

    /// Construct a loopback-only HTTP policy for local test harnesses.
    ///
    /// This escape hatch is absent from production release builds. It does not
    /// admit non-loopback HTTP origins.
    #[cfg(any(test, feature = "test-support"))]
    pub fn loopback_for_testing(
        issuer: impl Into<String>,
        trusted_origin: impl AsRef<str>,
    ) -> Result<Self, StatusListPolicyError> {
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(StatusListPolicyError::InvalidIssuer);
        }
        let origin = parse_status_origin(trusted_origin.as_ref(), true)?;
        Ok(Self {
            issuer,
            origins: BTreeSet::from([origin]),
            allow_loopback_http: true,
        })
    }

    fn permits(&self, issuer: &str, url: &Url) -> Result<(), VerificationError> {
        if self.issuer != issuer {
            return Err(VerificationError::StatusPolicy {
                code: "status.policy_issuer_mismatch",
            });
        }
        let origin = url.origin().ascii_serialization();
        if !self.origins.contains(&origin) {
            return Err(VerificationError::StatusPolicy {
                code: "status.origin_untrusted",
            });
        }
        Ok(())
    }

    fn fetch_url_policy(&self) -> FetchUrlPolicy {
        #[cfg(any(test, feature = "test-support"))]
        if self.allow_loopback_http {
            return FetchUrlPolicy::dev();
        }
        FetchUrlPolicy::strict()
    }
}

/// Invalid caller-owned status trust configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusListPolicyError {
    #[error("status-list issuer must not be empty")]
    InvalidIssuer,
    #[error("status-list origin must be an exact HTTPS origin")]
    InvalidOrigin,
    #[error("status-list origin contains URL credentials or resource components")]
    OriginHasResourceComponents,
    #[error("status-list origin allow-list exceeds the supported bound")]
    TooManyOrigins,
}

/// Caller-owned policy for explicit SD-JWT VC verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Issuer identifier expected in the `iss` claim.
    pub expected_issuer: String,
    /// Accepted JWS algorithms. Defaults to `EdDSA`.
    pub accepted_algorithms: BTreeSet<String>,
    /// Expected SD-JWT VC `vct`, when the caller wants a concrete profile.
    pub expected_vct: Option<String>,
    /// Allowed skew for `exp`, `nbf`, and future `iat` checks.
    pub clock_skew: Duration,
    /// Holder-binding policy for the embedded `cnf` confirmation.
    pub holder_binding: HolderBindingPolicy,
    /// Expected key-binding JWT audience for verifier-controlled challenges.
    pub expected_key_binding_audience: Option<String>,
    /// Expected key-binding JWT nonce for verifier-controlled challenges.
    pub expected_key_binding_nonce: Option<String>,
    /// Mandatory trust policy when the credential carries a status reference.
    pub status_list: Option<StatusListPolicy>,
    /// Test hook for deterministic time checks. Production callers should leave
    /// this unset.
    pub now: Option<OffsetDateTime>,
}

impl VerifyOptions {
    #[must_use]
    pub fn new(expected_issuer: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            accepted_algorithms: BTreeSet::from(["EdDSA".to_string()]),
            expected_vct: None,
            clock_skew: Duration::from_secs(60),
            holder_binding: HolderBindingPolicy::NotRequired,
            expected_key_binding_audience: None,
            expected_key_binding_nonce: None,
            status_list: None,
            now: None,
        }
    }

    #[must_use]
    pub fn expected_vct(mut self, expected_vct: impl Into<String>) -> Self {
        self.expected_vct = Some(expected_vct.into());
        self
    }

    #[must_use]
    pub fn accepted_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.accepted_algorithms = algorithms.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    #[must_use]
    pub fn holder_binding(mut self, holder_binding: HolderBindingPolicy) -> Self {
        self.holder_binding = holder_binding;
        self
    }

    #[must_use]
    pub fn key_binding_challenge(
        mut self,
        expected_audience: impl Into<String>,
        expected_nonce: impl Into<String>,
    ) -> Self {
        self.expected_key_binding_audience = Some(expected_audience.into());
        self.expected_key_binding_nonce = Some(expected_nonce.into());
        self
    }

    /// Configure fail-closed verification for status-bearing credentials.
    #[must_use]
    pub fn status_list(mut self, policy: StatusListPolicy) -> Self {
        self.status_list = Some(policy);
        self
    }

    #[must_use]
    pub fn now(mut self, now: OffsetDateTime) -> Self {
        self.now = Some(now);
        self
    }
}

/// Holder-binding expectation for the credential confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HolderBindingPolicy {
    /// Do not require a holder confirmation.
    NotRequired,
    /// Require `cnf.jwk`, and validate that it is a public JWK.
    Required,
    /// Require `cnf.jwk` and this exact `cnf.kid`.
    RequiredKid(String),
}

/// Verified credential metadata returned after successful verification.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedCredential {
    pub issuer: String,
    pub subject: Option<String>,
    pub credential_id: Option<String>,
    pub vct: String,
    pub key_id: String,
    pub algorithm: String,
    pub expires_at: i64,
    pub not_before: Option<i64>,
    pub issued_at: i64,
    pub disclosure_count: usize,
    pub holder_key_id: Option<String>,
}

impl fmt::Debug for VerifiedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCredential")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject.as_ref().map(|_| "<redacted>"))
            .field("credential_id", &self.credential_id)
            .field("vct", &self.vct)
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("expires_at", &self.expires_at)
            .field("not_before", &self.not_before)
            .field("issued_at", &self.issued_at)
            .field("disclosure_count", &self.disclosure_count)
            .field("holder_key_id", &self.holder_key_id)
            .finish()
    }
}

/// Redacted verifier error with a stable policy code.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("SD-JWT VC is malformed")]
    Malformed { code: &'static str },
    #[error("SD-JWT VC header uses an unsupported type")]
    HeaderType { code: &'static str },
    #[error("SD-JWT VC header contains an untrusted key reference")]
    UntrustedKeyReference { code: &'static str },
    #[error("SD-JWT VC algorithm is not accepted")]
    AlgorithmDisallowed { code: &'static str },
    #[error("SD-JWT VC signing key metadata does not match the header")]
    AlgorithmKeyMismatch { code: &'static str },
    #[error("SD-JWT VC signing key is missing")]
    MissingKeyId { code: &'static str },
    #[error("SD-JWT VC signing key is unknown")]
    UnknownKey { code: &'static str },
    #[error("SD-JWT VC signature is invalid")]
    InvalidSignature { code: &'static str },
    #[error("SD-JWT VC issuer does not match policy")]
    IssuerMismatch { code: &'static str },
    #[error("SD-JWT VC credential profile does not match policy")]
    VctMismatch { code: &'static str },
    #[error("SD-JWT VC time claim is invalid")]
    TimeClaim { code: &'static str },
    #[error("SD-JWT VC disclosure digest does not match")]
    DisclosureDigestMismatch { code: &'static str },
    #[error("SD-JWT VC holder binding does not match policy")]
    HolderBinding { code: &'static str },
    #[error("OID4VCI credential response does not contain a compact SD-JWT VC")]
    UnsupportedCredentialShape { code: &'static str },
    #[error("issuer JWKS could not be loaded")]
    JwksUnavailable { code: &'static str },
    #[error("credential status trust policy is missing or does not match")]
    StatusPolicy { code: &'static str },
    #[error("status-bearing credentials require the asynchronous client verifier")]
    StatusVerificationRequired { code: &'static str },
    #[error("credential status endpoint could not be reached safely")]
    StatusFetch { code: &'static str },
    #[error("credential status response does not satisfy transport policy")]
    StatusResponse { code: &'static str },
    #[error("credential status-list token is invalid")]
    StatusToken { code: &'static str },
    #[error("credential status is not valid")]
    CredentialStatus { code: &'static str },
}

impl VerificationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed { code }
            | Self::HeaderType { code }
            | Self::UntrustedKeyReference { code }
            | Self::AlgorithmDisallowed { code }
            | Self::AlgorithmKeyMismatch { code }
            | Self::MissingKeyId { code }
            | Self::UnknownKey { code }
            | Self::InvalidSignature { code }
            | Self::IssuerMismatch { code }
            | Self::VctMismatch { code }
            | Self::TimeClaim { code }
            | Self::DisclosureDigestMismatch { code }
            | Self::HolderBinding { code }
            | Self::UnsupportedCredentialShape { code }
            | Self::JwksUnavailable { code }
            | Self::StatusPolicy { code }
            | Self::StatusVerificationRequired { code }
            | Self::StatusFetch { code }
            | Self::StatusResponse { code }
            | Self::StatusToken { code }
            | Self::CredentialStatus { code } => code,
        }
    }

    #[must_use]
    pub const fn is_unknown_key(&self) -> bool {
        matches!(self, Self::UnknownKey { .. })
    }

    #[must_use]
    pub(crate) fn is_status_unknown_key(&self) -> bool {
        matches!(self, Self::StatusToken { code } if *code == "status.key.unknown")
    }

    pub(crate) const fn jwks_unavailable() -> Self {
        Self::JwksUnavailable {
            code: "jwks.unavailable",
        }
    }
}

/// Verify one status-free SD-JWT VC against caller-supplied trusted JWKS.
///
/// A status-bearing credential always fails with `status.policy_required` or
/// `status.fetch_required`. Use [`crate::RegistryNotaryClient::verify_sd_jwt_vc`]
/// so the status material is fetched and verified under [`StatusListPolicy`].
pub fn verify_sd_jwt_vc(
    compact: &str,
    jwks: &Value,
    options: &VerifyOptions,
) -> Result<VerifiedCredential, VerificationError> {
    let pending = verify_sd_jwt_vc_pending(compact, jwks, options)?;
    if pending.status.is_some() {
        return if options.status_list.is_some() {
            Err(VerificationError::StatusVerificationRequired {
                code: "status.fetch_required",
            })
        } else {
            Err(VerificationError::StatusPolicy {
                code: "status.policy_required",
            })
        };
    }
    Ok(pending.credential)
}

pub(crate) struct PendingCredentialVerification {
    pub(crate) credential: VerifiedCredential,
    pub(crate) status: Option<StatusListReference>,
}

#[derive(Clone)]
pub(crate) struct StatusListReference {
    uri: Url,
    index: u64,
}

pub(crate) fn verify_sd_jwt_vc_pending(
    compact: &str,
    jwks: &Value,
    options: &VerifyOptions,
) -> Result<PendingCredentialVerification, VerificationError> {
    let parsed = ParsedSdJwt::parse(compact)?;
    let header = decode_segment(parsed.header_b64)?;
    let payload = decode_segment(parsed.payload_b64)?;

    reject_untrusted_header_references(&header)?;
    let alg = required_string(&header, "alg")?;
    if !options.accepted_algorithms.contains(alg) {
        return Err(VerificationError::AlgorithmDisallowed {
            code: "algorithm.disallowed",
        });
    }
    if header.get("typ").and_then(Value::as_str) != Some(SD_JWT_VC_JWT_TYP) {
        return Err(VerificationError::HeaderType {
            code: "header.typ_mismatch",
        });
    }
    let kid = required_string(&header, "kid").map_err(|_| VerificationError::MissingKeyId {
        code: "key.missing",
    })?;
    let jwk = find_jwk(jwks, kid)?;
    if jwk_alg(&jwk) != Some(alg) || jwk.alg.as_deref().is_some_and(|jwk_alg| jwk_alg != alg) {
        return Err(VerificationError::AlgorithmKeyMismatch {
            code: "algorithm.key_mismatch",
        });
    }
    let signature =
        URL_SAFE_NO_PAD
            .decode(parsed.signature_b64)
            .map_err(|_| VerificationError::Malformed {
                code: "token.malformed",
            })?;
    verify(parsed.signing_input().as_bytes(), &signature, &jwk).map_err(|_| {
        VerificationError::InvalidSignature {
            code: "signature.invalid",
        }
    })?;

    verify_claims(&payload, &parsed, options, alg, kid)
}

fn verify_claims(
    payload: &Value,
    parsed: &ParsedSdJwt<'_>,
    options: &VerifyOptions,
    alg: &str,
    kid: &str,
) -> Result<PendingCredentialVerification, VerificationError> {
    let issuer = required_string(payload, "iss")?;
    if issuer != options.expected_issuer {
        return Err(VerificationError::IssuerMismatch {
            code: "claim.issuer_mismatch",
        });
    }
    let vct = required_string(payload, "vct")?;
    if options
        .expected_vct
        .as_deref()
        .is_some_and(|expected| expected != vct)
    {
        return Err(VerificationError::VctMismatch {
            code: "claim.vct_mismatch",
        });
    }

    let now = options
        .now
        .unwrap_or_else(OffsetDateTime::now_utc)
        .unix_timestamp();
    let skew = i64::try_from(options.clock_skew.as_secs()).unwrap_or(i64::MAX);
    let exp = required_i64(payload, "exp")?;
    let iat = required_i64(payload, "iat")?;
    let nbf = optional_i64(payload, "nbf")?;
    if exp <= now.saturating_sub(skew) || iat > now.saturating_add(skew) {
        return Err(VerificationError::TimeClaim {
            code: "claim.time_invalid",
        });
    }
    if let Some(nbf) = nbf {
        if nbf > now.saturating_add(skew) {
            return Err(VerificationError::TimeClaim {
                code: "claim.time_invalid",
            });
        }
    }

    let disclosed_status = verify_disclosures(payload, &parsed.disclosures)?;
    let holder_key_id = verify_holder_binding(HolderBindingContext {
        payload,
        policy: &options.holder_binding,
        key_binding_jwt: parsed.key_binding_jwt,
        sd_hash_input: parsed.sd_hash_input,
        expected_audience: options.expected_key_binding_audience.as_deref(),
        expected_nonce: options.expected_key_binding_nonce.as_deref(),
        now,
        skew,
    })?;
    let status = parse_status_reference(payload, disclosed_status.as_ref())?;
    let credential = VerifiedCredential {
        issuer: issuer.to_string(),
        subject: payload
            .get("sub")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        credential_id: payload
            .get("jti")
            .or_else(|| payload.get("id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        vct: vct.to_string(),
        key_id: kid.to_string(),
        algorithm: alg.to_string(),
        expires_at: exp,
        not_before: nbf,
        issued_at: iat,
        disclosure_count: parsed.disclosures.len(),
        holder_key_id,
    };
    Ok(PendingCredentialVerification { credential, status })
}

fn parse_status_reference(
    payload: &Value,
    disclosed_status: Option<&Value>,
) -> Result<Option<StatusListReference>, VerificationError> {
    let status = match (payload.get("status"), disclosed_status) {
        (None, None) => return Ok(None),
        (Some(status), None) | (None, Some(status)) => status,
        (Some(_), Some(_)) => {
            return Err(VerificationError::StatusToken {
                code: "status.reference_malformed",
            })
        }
    };
    let status_list = status
        .as_object()
        .and_then(|status| status.get("status_list"))
        .and_then(Value::as_object)
        .ok_or(VerificationError::StatusToken {
            code: "status.reference_malformed",
        })?;
    let index =
        status_list
            .get("idx")
            .and_then(Value::as_u64)
            .ok_or(VerificationError::StatusToken {
                code: "status.index.invalid",
            })?;
    let raw_uri = status_list
        .get("uri")
        .and_then(Value::as_str)
        .filter(|uri| !uri.is_empty() && uri.len() <= MAX_STATUS_LIST_URI_BYTES)
        .ok_or(VerificationError::StatusToken {
            code: "status.reference_malformed",
        })?;
    let uri = Url::parse(raw_uri).map_err(|_| VerificationError::StatusToken {
        code: "status.reference_malformed",
    })?;
    if uri.host().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(VerificationError::StatusToken {
            code: "status.reference_malformed",
        });
    }
    Ok(Some(StatusListReference { uri, index }))
}

pub(crate) async fn fetch_status_list_token(
    reference: &StatusListReference,
    options: &VerifyOptions,
) -> Result<String, VerificationError> {
    let policy = options
        .status_list
        .as_ref()
        .ok_or(VerificationError::StatusPolicy {
            code: "status.policy_required",
        })?;
    policy.permits(&options.expected_issuer, &reference.uri)?;
    let validated = policy
        .fetch_url_policy()
        .validate_for_immediate_fetch_with_timeout(&reference.uri, STATUS_LIST_DNS_TIMEOUT)
        .await
        .map_err(map_status_fetch_url_error)?;
    let response = validated
        .immediate_get_with_timeout(STATUS_LIST_FETCH_TIMEOUT)
        .map_err(map_status_fetch_url_error)?
        .header(ACCEPT, STATUS_LIST_MEDIA_TYPE)
        .header(ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|_| VerificationError::StatusFetch {
            code: "status.unreachable",
        })?;

    if response.status().is_redirection() {
        return Err(VerificationError::StatusFetch {
            code: "status.redirect_denied",
        });
    }
    if response.status() != StatusCode::OK {
        return Err(VerificationError::StatusResponse {
            code: "status.http_status_invalid",
        });
    }
    if !has_exact_status_list_media_type(response.headers()) {
        return Err(VerificationError::StatusResponse {
            code: "status.media_type_invalid",
        });
    }
    if !has_identity_content_encoding(response.headers()) {
        return Err(VerificationError::StatusResponse {
            code: "status.content_encoding_denied",
        });
    }
    let body = read_bounded(response, MAX_STATUS_LIST_RESPONSE_BYTES)
        .await
        .map_err(map_status_body_error)?;
    let compact = String::from_utf8(body).map_err(|_| VerificationError::StatusToken {
        code: "status.token_malformed",
    })?;
    if compact.trim() != compact || !is_compact_jws(&compact) {
        return Err(VerificationError::StatusToken {
            code: "status.token_malformed",
        });
    }
    Ok(compact)
}

pub(crate) fn verify_status_list_token(
    compact: &str,
    reference: &StatusListReference,
    jwks: &Value,
    options: &VerifyOptions,
) -> Result<(), VerificationError> {
    let mut parts = compact.split('.');
    let header_b64 =
        parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(VerificationError::StatusToken {
                code: "status.token_malformed",
            })?;
    let payload_b64 =
        parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(VerificationError::StatusToken {
                code: "status.token_malformed",
            })?;
    let signature_b64 =
        parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(VerificationError::StatusToken {
                code: "status.token_malformed",
            })?;
    if parts.next().is_some() {
        return Err(VerificationError::StatusToken {
            code: "status.token_malformed",
        });
    }

    let header = decode_status_segment(header_b64)?;
    if ["crit", "jku", "jwk", "x5u", "x5c"]
        .iter()
        .any(|forbidden| header.get(forbidden).is_some())
    {
        return Err(VerificationError::StatusToken {
            code: "status.header.untrusted_key_reference",
        });
    }
    if header.get("typ").and_then(Value::as_str) != Some("statuslist+jwt") {
        return Err(VerificationError::StatusToken {
            code: "status.header.typ_mismatch",
        });
    }
    let algorithm = status_required_string(&header, "alg")?;
    if !options.accepted_algorithms.contains(algorithm) {
        return Err(VerificationError::StatusToken {
            code: "status.algorithm.disallowed",
        });
    }
    let kid = status_required_string(&header, "kid")?;
    let jwk = find_jwk(jwks, kid).map_err(|_| VerificationError::StatusToken {
        code: "status.key.unknown",
    })?;
    if jwk_alg(&jwk) != Some(algorithm)
        || jwk
            .alg
            .as_deref()
            .is_some_and(|jwk_algorithm| jwk_algorithm != algorithm)
    {
        return Err(VerificationError::StatusToken {
            code: "status.algorithm.key_mismatch",
        });
    }
    let signature =
        URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| VerificationError::StatusToken {
                code: "status.token_malformed",
            })?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify(signing_input.as_bytes(), &signature, &jwk).map_err(|_| {
        VerificationError::StatusToken {
            code: "status.signature.invalid",
        }
    })?;

    let payload = decode_status_segment(payload_b64)?;
    let status_uri = reference.uri.as_str();
    if status_required_string(&payload, "iss")? != options.expected_issuer {
        return Err(VerificationError::StatusToken {
            code: "status.claim.issuer_mismatch",
        });
    }
    if status_required_string(&payload, "sub")? != status_uri {
        return Err(VerificationError::StatusToken {
            code: "status.claim.uri_mismatch",
        });
    }
    if !exact_audience_matches(&payload, status_uri) {
        return Err(VerificationError::StatusToken {
            code: "status.claim.audience_mismatch",
        });
    }
    verify_status_time_claims(&payload, options)?;
    let status = indexed_status(&payload, reference.index)?;
    match status {
        0 => Ok(()),
        1 => Err(VerificationError::CredentialStatus {
            code: "status.revoked",
        }),
        2 => Err(VerificationError::CredentialStatus {
            code: "status.suspended",
        }),
        _ => Err(VerificationError::CredentialStatus {
            code: "status.unknown",
        }),
    }
}

fn verify_status_time_claims(
    payload: &Value,
    options: &VerifyOptions,
) -> Result<(), VerificationError> {
    let now = options
        .now
        .unwrap_or_else(OffsetDateTime::now_utc)
        .unix_timestamp();
    let skew = i64::try_from(
        options
            .clock_skew
            .as_secs()
            .min(MAX_STATUS_LIST_CLOCK_SKEW_SECONDS),
    )
    .expect("bounded status clock skew fits i64");
    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(VerificationError::StatusToken {
            code: "status.claim.time_invalid",
        })?;
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(VerificationError::StatusToken {
            code: "status.claim.time_invalid",
        })?;
    let ttl = payload
        .get("ttl")
        .and_then(Value::as_i64)
        .filter(|ttl| *ttl > 0 && *ttl <= MAX_STATUS_LIST_TOKEN_LIFETIME_SECONDS)
        .ok_or(VerificationError::StatusToken {
            code: "status.claim.time_invalid",
        })?;
    let nbf = match payload.get("nbf") {
        None => None,
        Some(value) => Some(value.as_i64().ok_or(VerificationError::StatusToken {
            code: "status.claim.time_invalid",
        })?),
    };
    let lifetime = exp.checked_sub(iat).ok_or(VerificationError::StatusToken {
        code: "status.claim.time_invalid",
    })?;
    if lifetime <= 0
        || lifetime > ttl
        || exp <= now.saturating_sub(skew)
        || iat > now.saturating_add(skew)
        || nbf.is_some_and(|not_before| not_before > now.saturating_add(skew))
        || nbf.is_some_and(|not_before| not_before >= exp)
    {
        return Err(VerificationError::StatusToken {
            code: "status.claim.time_invalid",
        });
    }
    Ok(())
}

fn indexed_status(payload: &Value, index: u64) -> Result<u8, VerificationError> {
    let status_list = payload
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or(VerificationError::StatusToken {
            code: "status.list.malformed",
        })?;
    let bits = status_list
        .get("bits")
        .and_then(Value::as_u64)
        .filter(|bits| matches!(bits, 1 | 2 | 4 | 8))
        .ok_or(VerificationError::StatusToken {
            code: "status.list.malformed",
        })? as u8;
    let encoded = status_list
        .get("lst")
        .and_then(Value::as_str)
        .filter(|encoded| !encoded.is_empty())
        .ok_or(VerificationError::StatusToken {
            code: "status.list.malformed",
        })?;
    let compressed =
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| VerificationError::StatusToken {
                code: "status.list.malformed",
            })?;
    if compressed.len() > MAX_STATUS_LIST_COMPRESSED_BYTES {
        return Err(VerificationError::StatusToken {
            code: "status.list.compressed_too_large",
        });
    }
    let list = decompress_status_list(&compressed)?;
    let entries_per_byte = u64::from(8 / bits);
    let byte_index = index / entries_per_byte;
    let byte_index = usize::try_from(byte_index).map_err(|_| VerificationError::StatusToken {
        code: "status.index.invalid",
    })?;
    let byte = list
        .get(byte_index)
        .copied()
        .ok_or(VerificationError::StatusToken {
            code: "status.index.invalid",
        })?;
    let shift = u8::try_from((index % entries_per_byte) * u64::from(bits)).map_err(|_| {
        VerificationError::StatusToken {
            code: "status.index.invalid",
        }
    })?;
    let mask = if bits == 8 {
        u8::MAX
    } else {
        (1_u8 << bits) - 1
    };
    Ok((byte >> shift) & mask)
}

fn decompress_status_list(compressed: &[u8]) -> Result<Vec<u8>, VerificationError> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(MAX_STATUS_LIST_DECOMPRESSED_BYTES.min(8_192));
    (&mut decoder)
        .take((MAX_STATUS_LIST_DECOMPRESSED_BYTES + 1) as u64)
        .read_to_end(&mut decompressed)
        .map_err(|_| VerificationError::StatusToken {
            code: "status.list.malformed",
        })?;
    if decompressed.len() > MAX_STATUS_LIST_DECOMPRESSED_BYTES
        || decoder.total_in() != compressed.len() as u64
    {
        return Err(VerificationError::StatusToken {
            code: "status.list.decompression_limit",
        });
    }
    Ok(decompressed)
}

fn decode_status_segment(segment: &str) -> Result<Value, VerificationError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| VerificationError::StatusToken {
            code: "status.token_malformed",
        })?;
    serde_json::from_slice(&decoded).map_err(|_| VerificationError::StatusToken {
        code: "status.token_malformed",
    })
}

fn status_required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, VerificationError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(VerificationError::StatusToken {
            code: "status.token_malformed",
        })
}

fn exact_audience_matches(payload: &Value, expected: &str) -> bool {
    match payload.get("aud") {
        Some(Value::String(audience)) => audience == expected,
        Some(Value::Array(audiences)) if audiences.len() == 1 => {
            audiences[0].as_str() == Some(expected)
        }
        _ => false,
    }
}

fn has_exact_status_list_media_type(headers: &reqwest::header::HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None)
            if value
                .to_str()
                .is_ok_and(|value| value.eq_ignore_ascii_case(STATUS_LIST_MEDIA_TYPE))
    )
}

fn has_identity_content_encoding(headers: &reqwest::header::HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    match (values.next(), values.next()) {
        (None, None) => true,
        (Some(value), None) => value
            .to_str()
            .is_ok_and(|value| value.eq_ignore_ascii_case("identity")),
        _ => false,
    }
}

fn map_status_fetch_url_error(error: FetchUrlError) -> VerificationError {
    match error {
        FetchUrlError::Dns { .. }
        | FetchUrlError::NoAddresses
        | FetchUrlError::ValidationTimeout { .. }
        | FetchUrlError::ValidationTask(_) => VerificationError::StatusFetch {
            code: "status.unreachable",
        },
        _ => VerificationError::StatusFetch {
            code: "status.destination_unsafe",
        },
    }
}

fn map_status_body_error(error: BoundedReadError) -> VerificationError {
    match error {
        BoundedReadError::ContentLengthExceeded { .. }
        | BoundedReadError::BodyTooLarge { .. }
        | BoundedReadError::LengthOverflow => VerificationError::StatusResponse {
            code: "status.response_too_large",
        },
        BoundedReadError::Transport(_) => VerificationError::StatusFetch {
            code: "status.unreachable",
        },
        _ => VerificationError::StatusResponse {
            code: "status.response_invalid",
        },
    }
}

fn parse_status_origin(
    raw_origin: &str,
    allow_loopback_http: bool,
) -> Result<String, StatusListPolicyError> {
    if raw_origin.len() > MAX_STATUS_LIST_URI_BYTES {
        return Err(StatusListPolicyError::InvalidOrigin);
    }
    let origin = Url::parse(raw_origin).map_err(|_| StatusListPolicyError::InvalidOrigin)?;
    if origin.host().is_none() || origin.port() == Some(0) {
        return Err(StatusListPolicyError::InvalidOrigin);
    }
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(StatusListPolicyError::OriginHasResourceComponents);
    }
    let valid_scheme = origin.scheme() == "https"
        || (allow_loopback_http
            && origin.scheme() == "http"
            && matches!(origin.host_str(), Some("127.0.0.1" | "localhost" | "::1")));
    if !valid_scheme {
        return Err(StatusListPolicyError::InvalidOrigin);
    }
    Ok(origin.origin().ascii_serialization())
}

fn verify_disclosures(
    payload: &Value,
    disclosures: &[&str],
) -> Result<Option<Value>, VerificationError> {
    if disclosures.is_empty() && payload.get("_sd").is_none() {
        return Ok(None);
    }
    if payload.get("_sd_alg").and_then(Value::as_str) != Some("sha-256") {
        return Err(VerificationError::DisclosureDigestMismatch {
            code: "disclosure.digest_mismatch",
        });
    }
    let expected = payload
        .get("_sd")
        .and_then(Value::as_array)
        .ok_or(VerificationError::DisclosureDigestMismatch {
            code: "disclosure.digest_mismatch",
        })?
        .iter()
        .map(|digest| {
            digest.as_str().map(ToString::to_string).ok_or(
                VerificationError::DisclosureDigestMismatch {
                    code: "disclosure.digest_mismatch",
                },
            )
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut actual = BTreeSet::new();
    let mut disclosed_status = None;
    for disclosure in disclosures {
        let decoded = URL_SAFE_NO_PAD.decode(disclosure).map_err(|_| {
            VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            }
        })?;
        let value: Value = serde_json::from_slice(&decoded).map_err(|_| {
            VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            }
        })?;
        let Some(items) = value.as_array().filter(|items| items.len() >= 3) else {
            return Err(VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            });
        };
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
        if !expected.contains(&digest) || !actual.insert(digest) {
            return Err(VerificationError::DisclosureDigestMismatch {
                code: "disclosure.digest_mismatch",
            });
        }
        if items.get(1).and_then(Value::as_str) == Some("status")
            && disclosed_status.replace(items[2].clone()).is_some()
        {
            return Err(VerificationError::StatusToken {
                code: "status.reference_malformed",
            });
        }
    }
    Ok(disclosed_status)
}

struct HolderBindingContext<'a> {
    payload: &'a Value,
    policy: &'a HolderBindingPolicy,
    key_binding_jwt: Option<&'a str>,
    sd_hash_input: &'a str,
    expected_audience: Option<&'a str>,
    expected_nonce: Option<&'a str>,
    now: i64,
    skew: i64,
}

fn verify_holder_binding(
    context: HolderBindingContext<'_>,
) -> Result<Option<String>, VerificationError> {
    if matches!(context.policy, HolderBindingPolicy::NotRequired)
        && (context.key_binding_jwt.is_none()
            || context.expected_audience.is_none()
            || context.expected_nonce.is_none())
    {
        return Ok(context
            .payload
            .get("cnf")
            .and_then(|cnf| cnf.get("kid"))
            .and_then(Value::as_str)
            .map(ToString::to_string));
    }
    let cnf = context
        .payload
        .get("cnf")
        .ok_or(VerificationError::HolderBinding {
            code: "holder_binding.required",
        })?;
    let jwk_value = cnf.get("jwk").ok_or(VerificationError::HolderBinding {
        code: "holder_binding.required",
    })?;
    let jwk_json =
        serde_json::to_string(jwk_value).map_err(|_| VerificationError::HolderBinding {
            code: "holder_binding.invalid",
        })?;
    let holder_jwk = PublicJwk::parse(&jwk_json).map_err(|_| VerificationError::HolderBinding {
        code: "holder_binding.invalid",
    })?;
    let actual_kid = cnf
        .get("kid")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    if let HolderBindingPolicy::RequiredKid(expected) = context.policy {
        if actual_kid.as_deref() != Some(expected.as_str()) {
            return Err(VerificationError::HolderBinding {
                code: "holder_binding.kid_mismatch",
            });
        }
    }
    if context.key_binding_jwt.is_none()
        && context.expected_audience.is_some()
        && context.expected_nonce.is_some()
    {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.challenge_required",
        });
    }
    if let Some(key_binding_jwt) = context.key_binding_jwt {
        verify_key_binding_jwt(
            key_binding_jwt,
            context.sd_hash_input,
            &holder_jwk,
            context.expected_audience,
            context.expected_nonce,
            context.now,
            context.skew,
        )?;
    }
    Ok(actual_kid)
}

fn verify_key_binding_jwt(
    compact: &str,
    sd_hash_input: &str,
    holder_jwk: &PublicJwk,
    expected_audience: Option<&str>,
    expected_nonce: Option<&str>,
    now: i64,
    skew: i64,
) -> Result<(), VerificationError> {
    let mut parts = compact.split('.');
    let header_b64 = parts.next().ok_or(VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    let payload_b64 = parts.next().ok_or(VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    let signature_b64 = parts.next().ok_or(VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    if parts.next().is_some()
        || header_b64.is_empty()
        || payload_b64.is_empty()
        || signature_b64.is_empty()
    {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let header = decode_segment(header_b64).map_err(|_| VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    reject_untrusted_header_references(&header)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || header.get("typ").and_then(Value::as_str) != Some("kb+jwt")
    {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let signature =
        URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| VerificationError::HolderBinding {
                code: "holder_binding.proof_invalid",
            })?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify(signing_input.as_bytes(), &signature, holder_jwk).map_err(|_| {
        VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        }
    })?;
    let payload = decode_segment(payload_b64).map_err(|_| VerificationError::HolderBinding {
        code: "holder_binding.proof_invalid",
    })?;
    let iat =
        payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or(VerificationError::HolderBinding {
                code: "holder_binding.proof_invalid",
            })?;
    if iat > now.saturating_add(skew) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let exp =
        payload
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or(VerificationError::HolderBinding {
                code: "holder_binding.proof_invalid",
            })?;
    if exp <= now.saturating_sub(skew) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    if payload
        .get("nbf")
        .and_then(Value::as_i64)
        .is_some_and(|nbf| nbf > now.saturating_add(skew))
    {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let expected_sd_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(sd_hash_input.as_bytes()));
    if payload.get("sd_hash").and_then(Value::as_str) != Some(expected_sd_hash.as_str()) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    let (Some(expected_audience), Some(expected_nonce)) = (expected_audience, expected_nonce)
    else {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.challenge_required",
        });
    };
    if !audience_matches(&payload, expected_audience) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    if payload.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
        return Err(VerificationError::HolderBinding {
            code: "holder_binding.proof_invalid",
        });
    }
    Ok(())
}

fn audience_matches(payload: &Value, expected_audience: &str) -> bool {
    match payload.get("aud") {
        Some(Value::String(audience)) => audience == expected_audience,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|audience| audience.as_str() == Some(expected_audience)),
        _ => false,
    }
}

fn reject_untrusted_header_references(header: &Value) -> Result<(), VerificationError> {
    for forbidden in ["crit", "jku", "jwk", "x5u", "x5c"] {
        if header.get(forbidden).is_some() {
            return Err(VerificationError::UntrustedKeyReference {
                code: "header.untrusted_key_reference",
            });
        }
    }
    Ok(())
}

fn find_jwk(jwks: &Value, kid: &str) -> Result<PublicJwk, VerificationError> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(VerificationError::UnknownKey {
            code: "key.unknown",
        })?;
    for key in keys {
        if key.get("kid").and_then(Value::as_str) == Some(kid) {
            let json = serde_json::to_string(key).map_err(|_| VerificationError::UnknownKey {
                code: "key.unknown",
            })?;
            return PublicJwk::parse(&json).map_err(|_| VerificationError::UnknownKey {
                code: "key.unknown",
            });
        }
    }
    Err(VerificationError::UnknownKey {
        code: "key.unknown",
    })
}

fn jwk_alg(jwk: &PublicJwk) -> Option<&'static str> {
    match jwk.algorithm().ok()? {
        SigningAlgorithm::EdDsa => Some("EdDSA"),
        SigningAlgorithm::Rs256 => Some("RS256"),
        SigningAlgorithm::Es256 => Some("ES256"),
    }
}

fn decode_segment(segment: &str) -> Result<Value, VerificationError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| VerificationError::Malformed {
            code: "token.malformed",
        })?;
    serde_json::from_slice(&decoded).map_err(|_| VerificationError::Malformed {
        code: "token.malformed",
    })
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, VerificationError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })
}

fn required_i64(value: &Value, field: &str) -> Result<i64, VerificationError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(VerificationError::TimeClaim {
            code: "claim.time_invalid",
        })
}

fn optional_i64(value: &Value, field: &str) -> Result<Option<i64>, VerificationError> {
    value
        .get(field)
        .map(|raw| {
            raw.as_i64().ok_or(VerificationError::TimeClaim {
                code: "claim.time_invalid",
            })
        })
        .transpose()
}

struct ParsedSdJwt<'a> {
    header_b64: &'a str,
    payload_b64: &'a str,
    signature_b64: &'a str,
    disclosures: Vec<&'a str>,
    key_binding_jwt: Option<&'a str>,
    sd_hash_input: &'a str,
}

impl<'a> ParsedSdJwt<'a> {
    fn parse(compact: &'a str) -> Result<Self, VerificationError> {
        let mut parts = compact.split('~');
        let issuer_jwt =
            parts
                .next()
                .filter(|part| !part.is_empty())
                .ok_or(VerificationError::Malformed {
                    code: "token.malformed",
                })?;
        let mut presentation_parts = parts.filter(|part| !part.is_empty()).collect::<Vec<_>>();
        let key_binding_jwt = presentation_parts
            .last()
            .copied()
            .filter(|part| is_compact_jws(part));
        if key_binding_jwt.is_some() {
            presentation_parts.pop();
        }
        if presentation_parts.iter().any(|part| is_compact_jws(part)) {
            return Err(VerificationError::Malformed {
                code: "token.malformed",
            });
        }
        let sd_hash_input = if let Some(key_binding_jwt) = key_binding_jwt {
            compact
                .strip_suffix(key_binding_jwt)
                .ok_or(VerificationError::Malformed {
                    code: "token.malformed",
                })?
        } else {
            compact
        };
        let mut jwt_parts = issuer_jwt.split('.');
        let header_b64 = jwt_parts.next().ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })?;
        let payload_b64 = jwt_parts.next().ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })?;
        let signature_b64 = jwt_parts.next().ok_or(VerificationError::Malformed {
            code: "token.malformed",
        })?;
        if jwt_parts.next().is_some()
            || header_b64.is_empty()
            || payload_b64.is_empty()
            || signature_b64.is_empty()
        {
            return Err(VerificationError::Malformed {
                code: "token.malformed",
            });
        }
        Ok(Self {
            header_b64,
            payload_b64,
            signature_b64,
            disclosures: presentation_parts,
            key_binding_jwt,
            sd_hash_input,
        })
    }

    fn signing_input(&self) -> String {
        format!("{}.{}", self.header_b64, self.payload_b64)
    }
}

fn is_compact_jws(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(header) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let Some(signature) = parts.next() else {
        return false;
    };
    parts.next().is_none() && !header.is_empty() && !payload.is_empty() && !signature.is_empty()
}

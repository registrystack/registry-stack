// SPDX-License-Identifier: Apache-2.0
//! A bounded external verdict transport. Durable quarantine, retries and
//! release authority remain with the calling product's worker and its
//! database transaction boundary.
//!
//! One attempt is one `POST` of the exact content bytes to the configured
//! URL with `Authorization: Bearer <credential>`, the content's own
//! `Content-Type`, `Accept: application/json`, and `x-content-sha256` set to
//! the lowercase hex SHA-256 of the body. Only a `200` whose body is at most
//! 1024 bytes and exactly `{"verdict":"approved"}` or
//! `{"verdict":"rejected"}` is a verdict; every other outcome is
//! [`VerifierError::Unavailable`]. The `policyId` is not sent: it names the
//! scanner and rules generation the operator bound the URL to, and enters
//! only the binding digest a product records beside each verdict.

use std::{fmt, net::IpAddr, time::Duration};

use registry_platform_config::{
    AttachmentVerifierConfig, ProtectedSecret, SecretReference, SecretResolver,
};
use registry_platform_httputil::{read_bounded, validate_response_headers, OutboundClientBuilder};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    StatusCode, Url,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const MAXIMUM_VERDICT_BYTES: u64 = 1024;
const MAXIMUM_URL_BYTES: usize = 2048;
const MAXIMUM_POLICY_ID_BYTES: usize = 128;
const MAXIMUM_SECRET_BYTES: usize = 4096;
const MAXIMUM_CONTENT_TYPE_BYTES: usize = 255;
const MAXIMUM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Verifier failures carry no URLs, credentials or verifier responses.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerifierError {
    #[error("content verification configuration is invalid")]
    InvalidConfiguration,
    #[error("content verification secret resolution failed")]
    Secret,
    #[error("content verification is unavailable")]
    Unavailable,
    #[error("content verification input failed integrity validation")]
    Integrity,
}

type Result<T> = std::result::Result<T, VerifierError>;

/// The verifier's terminal answer for one content digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Approved,
    Rejected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictResponse {
    verdict: Verdict,
}

/// What the calling product fixes about its verification binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierNamespace {
    /// 1 to 128 printable ASCII characters, for example
    /// `breg-attachment-verification-http-v1`.
    pub binding_domain: &'static str,
    /// The largest content submitted, in bytes.
    pub max_content_bytes: u64,
}

impl VerifierNamespace {
    fn check(&self) -> Result<()> {
        if self.binding_domain.is_empty()
            || self.binding_domain.len() > 128
            || !self.binding_domain.bytes().all(|b| b.is_ascii_graphic())
            || self.max_content_bytes == 0
        {
            return Err(VerifierError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Validated, unresolved verifier settings. Debug never reveals deployment values.
#[derive(Clone)]
pub struct HttpVerifierSettings {
    url: Url,
    authorization_ref: SecretReference,
    policy_id: String,
    timeout: Duration,
}

impl HttpVerifierSettings {
    /// Refuse what the shared block's decode does not: a non-loopback `http`
    /// URL, a URL with a fragment or surrounding whitespace, and a
    /// `policyId` that is empty, longer than 128 bytes, or not printable
    /// ASCII.
    pub fn from_config(config: &AttachmentVerifierConfig) -> Result<Self> {
        let text = config.url.as_str();
        let url = Url::parse(text).map_err(|_| VerifierError::InvalidConfiguration)?;
        let loopback = url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        let policy_id = config.policy_id.as_str();
        if text.len() > MAXIMUM_URL_BYTES
            || text.trim() != text
            || text.chars().any(char::is_control)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || policy_id.is_empty()
            || policy_id.len() > MAXIMUM_POLICY_ID_BYTES
            || !policy_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(VerifierError::InvalidConfiguration);
        }
        Ok(Self {
            url,
            authorization_ref: config.authorization_ref.clone(),
            policy_id: policy_id.to_owned(),
            timeout: Duration::from_millis(config.attempt_timeout_milliseconds.get()),
        })
    }

    /// Resolve the bearer credential and bind the verifier to `namespace`,
    /// the URL and the policy. Nothing is sent.
    pub fn activate(
        &self,
        namespace: VerifierNamespace,
        resolver: &SecretResolver,
    ) -> Result<HttpVerifier> {
        namespace.check()?;
        let authorization = resolver
            .resolve_reference(&self.authorization_ref)
            .map_err(|_| VerifierError::Secret)?;
        if authorization.is_empty()
            || authorization.len() > MAXIMUM_SECRET_BYTES
            || !authorization
                .expose_secret()
                .iter()
                .all(u8::is_ascii_graphic)
        {
            return Err(VerifierError::Secret);
        }
        Ok(HttpVerifier {
            client: OutboundClientBuilder::new()
                .timeout(self.timeout)
                .connect_timeout(connect_timeout(self.timeout))
                .try_build()
                .map_err(|_| VerifierError::InvalidConfiguration)?,
            binding_digest: binding_digest(namespace, &self.url, &self.policy_id)?,
            namespace,
            url: self.url.clone(),
            authorization,
        })
    }
}

impl fmt::Debug for HttpVerifierSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpVerifierSettings(<redacted>)")
    }
}

/// The connect phase of one attempt never outlasts the attempt, and never
/// waits more than five seconds.
fn connect_timeout(timeout: Duration) -> Duration {
    timeout.min(MAXIMUM_CONNECT_TIMEOUT)
}

/// The hex SHA-256 of the JSON array `[domain, url, policyId]`: it changes
/// when the URL or policy generation does, and survives a credential
/// rotation or timeout change.
fn binding_digest(namespace: VerifierNamespace, url: &Url, policy_id: &str) -> Result<String> {
    let identity = serde_json::to_vec(&(namespace.binding_domain, url.as_str(), policy_id))
        .map_err(|_| VerifierError::InvalidConfiguration)?;
    Ok(hex::encode(Sha256::digest(identity)))
}

/// One activated verifier.
pub struct HttpVerifier {
    client: reqwest::Client,
    namespace: VerifierNamespace,
    url: Url,
    authorization: ProtectedSecret,
    binding_digest: String,
}

impl fmt::Debug for HttpVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpVerifier(<redacted>)")
    }
}

impl HttpVerifier {
    /// Persist beside each verdict; a changed binding cannot reuse it.
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    /// The caller must bind this verdict to the exact retained digest and
    /// policy generation. Transport errors leave quarantine intact and are
    /// retryable.
    pub async fn verify(
        &self,
        sha256: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Verdict> {
        let headers = self.request_headers(sha256, content_type, &bytes)?;
        let response = self
            .client
            .post(self.url.clone())
            .headers(headers)
            .body(bytes)
            .send()
            .await
            .map_err(|_| VerifierError::Unavailable)?;
        validate_response_headers(response.headers()).map_err(|_| VerifierError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(VerifierError::Unavailable);
        }
        let bytes = read_bounded(response, MAXIMUM_VERDICT_BYTES)
            .await
            .map_err(|_| VerifierError::Unavailable)?;
        let result: VerdictResponse =
            serde_json::from_slice(&bytes).map_err(|_| VerifierError::Unavailable)?;
        Ok(result.verdict)
    }

    fn request_headers(&self, sha256: &str, content_type: &str, bytes: &[u8]) -> Result<HeaderMap> {
        if bytes.len() as u64 > self.namespace.max_content_bytes
            || sha256.len() != 64
            || hex::encode(Sha256::digest(bytes)) != sha256
            || content_type.is_empty()
            || content_type.len() > MAXIMUM_CONTENT_TYPE_BYTES
            || !content_type.is_ascii()
        {
            return Err(VerifierError::Integrity);
        }
        let content_type =
            HeaderValue::from_str(content_type).map_err(|_| VerifierError::Integrity)?;
        let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
        bearer.extend_from_slice(self.authorization.expose_secret());
        let mut authorization =
            HeaderValue::from_bytes(&bearer).map_err(|_| VerifierError::Secret)?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        headers.insert(reqwest::header::CONTENT_TYPE, content_type);
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            "x-content-sha256",
            HeaderValue::from_str(sha256).map_err(|_| VerifierError::Integrity)?,
        );
        Ok(headers)
    }
}

#[cfg(test)]
#[path = "verifier_tests.rs"]
mod tests;

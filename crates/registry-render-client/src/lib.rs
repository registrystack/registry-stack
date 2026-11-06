// SPDX-License-Identifier: Apache-2.0
//! Thin client for the Render HTTP adapter. Rendering and sealing are one
//! exchange each; a correlation key is never treated as an idempotency or
//! deduplication promise.
use base64::Engine as _;
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{fmt, time::Duration};
use url::Url;

pub use registry_platform_httputil::client::{BearerToken, TransportKind};

// The server permits 32 pointers of 256 Unicode scalar values. JSON escaping
// uses at most six bytes per scalar, leaving room for the fixed problem fields.
const MAXIMUM_PROBLEM_BYTES: u64 = 64 * 1024;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderClientConfig {
    pub base_url: String,
    #[serde(default = "attempt_timeout")]
    pub attempt_timeout_milliseconds: u64,
    #[serde(default = "connect_timeout")]
    pub connect_timeout_milliseconds: u64,
    #[serde(default = "response_limit")]
    pub maximum_response_bytes: u64,
    #[serde(default)]
    pub trusted_root_certificates: Option<String>,
}
fn attempt_timeout() -> u64 {
    30_000
}
fn connect_timeout() -> u64 {
    10_000
}
fn response_limit() -> u64 {
    16 * 1024 * 1024
}
impl RenderClientConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            attempt_timeout_milliseconds: attempt_timeout(),
            connect_timeout_milliseconds: connect_timeout(),
            maximum_response_bytes: response_limit(),
            trusted_root_certificates: None,
        }
    }
}

/// A rendered document. A member the server adds later is ignored; the
/// members below are checked before the document is returned.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedDocument {
    pub pdf_base64: String,
    pub pdf_sha256: String,
    pub data_sha256: String,
    pub document_version: String,
    pub warnings: Vec<String>,
}

/// The PAdES level of a seal, as the server names it in `seal.level`: the
/// baseline level as ETSI EN 319 142-1 writes it, `B-B` or `B-T`. A level
/// this client does not know is refused as `protocol`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SealLevel {
    /// PAdES baseline B (no timestamp).
    #[serde(rename = "B-B")]
    BaselineB,
    /// PAdES baseline T (signature timestamp).
    #[serde(rename = "B-T")]
    BaselineT,
}
impl SealLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaselineB => "B-B",
            Self::BaselineT => "B-T",
        }
    }
}

/// The facts the server reports about a seal; none is verified by the client
/// beyond shape and consistency with the level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SealFacts {
    pub id: String,
    pub level: SealLevel,
    pub certificate_sha256: String,
    /// The timestamp authority's `genTime`, RFC 3339 at the precision the
    /// authority gave; present exactly at level `B-T`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamped_at: Option<String>,
    /// Whether the server declares the seal `trust: test-only`: a test
    /// seal's documents are not official.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub test_only: bool,
}

/// A sealed document. There is no `pdfSha256`: `document_sha256` covers the
/// first revision (the rendered document) and `signed_file_sha256` the whole
/// signed file in `pdf`. `bundle_hash` is the package the server rendered
/// from, so a caller holding only `render:seal` can pin it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SealedDocument {
    pub pdf: Vec<u8>,
    pub document_sha256: String,
    pub signed_file_sha256: String,
    pub data_sha256: String,
    pub document_version: String,
    pub bundle_hash: String,
    pub warnings: Vec<String>,
    pub seal: SealFacts,
}

/// The sealed answer as sent. A member the server adds later is ignored,
/// except `pdfSha256`, which the sealed contract excludes.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealedWire {
    pdf_base64: String,
    document_sha256: String,
    signed_file_sha256: String,
    data_sha256: String,
    document_version: String,
    bundle_hash: String,
    warnings: Vec<String>,
    seal: SealWire,
    #[serde(default)]
    pdf_sha256: Option<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealWire {
    id: String,
    level: String,
    certificate_sha256: String,
    #[serde(default)]
    timestamped_at: Option<String>,
    #[serde(default)]
    test_only: bool,
}

#[derive(Clone, Debug, Serialize, thiserror::Error)]
#[error("Registry Render client failed ({kind})")]
#[serde(rename_all = "camelCase")]
pub struct RenderClientError {
    pub kind: &'static str,
    pub outcome_unknown: bool,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_transport_kind"
    )]
    pub transport_kind: Option<TransportKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}
fn error(kind: &'static str) -> RenderClientError {
    RenderClientError {
        kind,
        outcome_unknown: kind == "protocol",
        transport_kind: None,
        status: None,
        code: None,
        trace_id: None,
    }
}

fn serialize_transport_kind<S: serde::Serializer>(
    kind: &Option<TransportKind>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    kind.map(|kind| kind.kind()).serialize(serializer)
}
fn transport_error(kind: TransportKind) -> RenderClientError {
    RenderClientError {
        outcome_unknown: kind != TransportKind::Connect,
        transport_kind: Some(kind),
        ..error("transport")
    }
}
impl RenderClientError {
    /// A local argument refusal, before an HTTP exchange.
    pub fn invalid_request() -> Self {
        error("invalid-request")
    }
}

pub struct RenderClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    maximum_response_bytes: u64,
}
impl fmt::Debug for RenderClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderClient").finish_non_exhaustive()
    }
}
impl RenderClient {
    pub fn new(config: RenderClientConfig) -> Result<Self, RenderClientError> {
        if !(1..=300_000).contains(&config.attempt_timeout_milliseconds)
            || !(1..=300_000).contains(&config.connect_timeout_milliseconds)
            || !(1024..=32 * 1024 * 1024).contains(&config.maximum_response_bytes)
        {
            return Err(error("configuration"));
        }
        let base_url =
            ServiceBaseUrl::new(Url::parse(&config.base_url).map_err(|_| error("configuration"))?)
                .map_err(|_| error("configuration"))?;
        let http = build_client(OutboundOptions {
            request_timeout: Duration::from_millis(config.attempt_timeout_milliseconds),
            connect_timeout: Duration::from_millis(config.connect_timeout_milliseconds),
            user_agent: None,
            trusted_root_certificates: config
                .trusted_root_certificates
                .as_deref()
                .map(str::as_bytes),
        })
        .map_err(|_| error("configuration"))?;
        Ok(Self {
            http,
            base_url,
            maximum_response_bytes: config.maximum_response_bytes,
        })
    }

    /// Validate before token acquisition in a language facade. No network effects.
    pub fn validate_request(
        document_type: &str,
        request: &Value,
    ) -> Result<Vec<u8>, RenderClientError> {
        if document_type.is_empty()
            || document_type.len() > 64
            || !document_type
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(error("invalid-request"));
        }
        let object = request
            .as_object()
            .ok_or_else(|| error("invalid-request"))?;
        if object
            .keys()
            .any(|key| !["locale", "issuedAt", "data", "assets"].contains(&key.as_str()))
            || object
                .get("issuedAt")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || !object.contains_key("data")
            || object.get("locale").is_some_and(|value| !value.is_string())
            || object.get("assets").is_some_and(|value| !value.is_object())
        {
            return Err(error("invalid-request"));
        }
        let bytes = serde_json::to_vec(request).map_err(|_| error("invalid-request"))?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(error("invalid-request"));
        }
        chrono::DateTime::parse_from_rfc3339(
            object["issuedAt"].as_str().expect("validated string"),
        )
        .map_err(|_| error("invalid-request"))?;
        if let Some(assets) = object.get("assets").and_then(Value::as_object) {
            let mut total = 0usize;
            for (name, encoded) in assets {
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                {
                    return Err(error("invalid-request"));
                }
                let encoded = encoded.as_str().ok_or_else(|| error("invalid-request"))?;
                const MAXIMUM_ASSET_BYTES: usize = 2 * 1024 * 1024;
                if encoded.len() > MAXIMUM_ASSET_BYTES.div_ceil(3) * 4 {
                    return Err(error("invalid-request"));
                }
                let asset = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| error("invalid-request"))?;
                total = total
                    .checked_add(asset.len())
                    .ok_or_else(|| error("invalid-request"))?;
                let jpeg = asset.len() > 3 && asset.starts_with(&[0xff, 0xd8]);
                let png = asset.len() > 8
                    && asset.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
                if asset.len() > MAXIMUM_ASSET_BYTES || total > 8 * 1024 * 1024 || !(jpeg || png) {
                    return Err(error("invalid-request"));
                }
            }
        }
        Ok(bytes)
    }

    /// Render once with a caller-acquired credential for this Render resource.
    pub async fn render(
        &self,
        token: &BearerToken,
        document_type: &str,
        request: &Value,
    ) -> Result<RenderedDocument, RenderClientError> {
        let body = Self::validate_request(document_type, request)?;
        let value = self
            .exchange(token, Route::Render, document_type, body, None)
            .await?;
        let document: RenderedDocument =
            serde_json::from_value(value).map_err(|_| error("protocol"))?;
        let pdf = base64::engine::general_purpose::STANDARD
            .decode(&document.pdf_base64)
            .map_err(|_| error("protocol"))?;
        if !pdf.starts_with(b"%PDF-")
            || !is_digest(&document.pdf_sha256)
            || !is_digest(&document.data_sha256)
            || hex::encode(Sha256::digest(&pdf)) != document.pdf_sha256
            || !bounded_version_and_warnings(
                document_type,
                &document.document_version,
                &document.warnings,
            )
        {
            return Err(error("protocol"));
        }
        Ok(document)
    }

    /// Render and seal once (PAdES) with a caller-acquired credential carrying
    /// the `render:seal` scope. The route exists only on a deployment that
    /// configures seals; otherwise the answer is the `render.not-found` problem.
    ///
    /// This is a single exchange and is never resent: a second seal of the
    /// same request is a second valid file with another signing time (and,
    /// at level B-T, another timestamp token), so the client cannot treat a
    /// repeat as harmless. After a timeout or broken exchange
    /// (`outcome_unknown`) the caller decides whether another file is wanted.
    /// `idempotency_key` is an optional correlation key (1 to 128 visible
    /// ASCII characters). It is sent as `Idempotency-Key` and the server must
    /// echo it exactly; it is audited by the server, not a deduplication
    /// promise.
    ///
    /// Before returning, the client checks that the bytes hash to
    /// `signedFileSha256`, that they start as a PDF, that
    /// `documentSha256` equals the SHA-256 of a prefix of the file ending at
    /// one of its `%%EOF` markers (found by byte search, without parsing PDF),
    /// and that the seal facts are consistent with the level. It does not
    /// verify the signature, the certificate chain or the timestamp token;
    /// that is the relying party's validation.
    pub async fn seal(
        &self,
        token: &BearerToken,
        document_type: &str,
        request: &Value,
        idempotency_key: Option<&str>,
    ) -> Result<SealedDocument, RenderClientError> {
        let body = Self::validate_request(document_type, request)?;
        if let Some(key) = idempotency_key {
            if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Err(error("invalid-request"));
            }
        }
        let value = self
            .exchange(token, Route::Seal, document_type, body, idempotency_key)
            .await?;
        let wire: SealedWire = serde_json::from_value(value).map_err(|_| error("protocol"))?;
        let pdf = base64::engine::general_purpose::STANDARD
            .decode(&wire.pdf_base64)
            .map_err(|_| error("protocol"))?;
        let level = match wire.seal.level.as_str() {
            "B-B" => SealLevel::BaselineB,
            "B-T" => SealLevel::BaselineT,
            _ => return Err(error("protocol")),
        };
        let timestamp_consistent = match (level, &wire.seal.timestamped_at) {
            (SealLevel::BaselineB, None) => true,
            (SealLevel::BaselineT, Some(time)) => {
                time.len() <= 64 && chrono::DateTime::parse_from_rfc3339(time).is_ok()
            }
            _ => false,
        };
        if !pdf.starts_with(b"%PDF-")
            || wire.pdf_sha256.is_some()
            || !is_digest(&wire.document_sha256)
            || !is_digest(&wire.signed_file_sha256)
            || !is_digest(&wire.data_sha256)
            || !is_digest(&wire.bundle_hash)
            || !is_digest(&wire.seal.certificate_sha256)
            || hex::encode(Sha256::digest(&pdf)) != wire.signed_file_sha256
            || !first_revision_matches(&pdf, &wire.document_sha256)
            || !timestamp_consistent
            || wire.seal.id.is_empty()
            || wire.seal.id.len() > 256
            || !bounded_version_and_warnings(document_type, &wire.document_version, &wire.warnings)
        {
            return Err(error("protocol"));
        }
        Ok(SealedDocument {
            pdf,
            document_sha256: wire.document_sha256,
            signed_file_sha256: wire.signed_file_sha256,
            data_sha256: wire.data_sha256,
            document_version: wire.document_version,
            bundle_hash: wire.bundle_hash,
            warnings: wire.warnings,
            seal: SealFacts {
                id: wire.seal.id,
                level,
                certificate_sha256: wire.seal.certificate_sha256,
                timestamped_at: wire.seal.timestamped_at,
                test_only: wire.seal.test_only,
            },
        })
    }

    /// One POST, strict header, media type and problem validation. Returns the
    /// success body; every refusal is a typed error.
    async fn exchange(
        &self,
        token: &BearerToken,
        route: Route,
        document_type: &str,
        body: Vec<u8>,
        idempotency_key: Option<&str>,
    ) -> Result<Value, RenderClientError> {
        let url = self
            .base_url
            .join(&format!("v1/{}/{document_type}", route.segment()))
            .map_err(|_| error("invalid-request"))?;
        let mut builder = self
            .http
            .post(url)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json");
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key);
        }
        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|error| transport_error(send_failure_kind(&error)))?;
        validate_response_headers(response.headers()).map_err(|_| error("protocol"))?;
        let trace = response_trace_id(response.headers())
            .map_err(|_| error("protocol"))?
            .to_owned();
        let status = response.status();
        let mut content_types = response.headers().get_all(CONTENT_TYPE).iter();
        let content_type = content_types
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| error("protocol"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if content_types.next().is_some()
            || content_type
                != if status.is_success() {
                    "application/json"
                } else {
                    "application/problem+json"
                }
        {
            return Err(error("protocol"));
        }
        let limit = if status.is_success() {
            self.maximum_response_bytes
        } else {
            MAXIMUM_PROBLEM_BYTES
        };
        let echoed: Vec<Option<String>> = response
            .headers()
            .get_all("idempotency-key")
            .iter()
            .map(|value| value.to_str().ok().map(str::to_owned))
            .collect();
        let bytes = read_bounded(response, limit)
            .await
            .map_err(|error| transport_error(read_failure_kind(&error)))?;
        let value = parse_json_strict(&bytes).map_err(|_| error("protocol"))?;
        if !status.is_success() {
            let mut fields = value
                .as_object()
                .cloned()
                .ok_or_else(|| error("protocol"))?;
            let pointers: Vec<String> = fields
                .remove("pointers")
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| error("protocol"))?
                .unwrap_or_default();
            let problem: ProblemDocument =
                serde_json::from_value(Value::Object(fields)).map_err(|_| error("protocol"))?;
            let slug = problem
                .code
                .strip_prefix("render.")
                .ok_or_else(|| error("protocol"))?;
            let expected_status = match slug {
                "unauthorized" => 401,
                "forbidden" => 403,
                "authentication-unavailable" => 503,
                "not-found" => 404,
                "body-too-large" => 413,
                "rate-limited" => 429,
                "compile-failed" | "strict-warnings" | "output-too-large" => 422,
                "render-timeout" => 504,
                "audit-failed" | "runtime-invalid" => 503,
                "signing-unavailable" | "seal-certificate-invalid" if route == Route::Seal => 503,
                "timestamp-failed" if route == Route::Seal => 502,
                "document-not-sealable" if route == Route::Seal => 400,
                "seal-client-not-allowed" if route == Route::Seal => 403,
                "internal" | "render-panicked" => 500,
                "invalid-argument" | "manifest-invalid" | "bundle-tampered" | "bundle-unsealed"
                | "unknown-document" | "labels-invalid" | "font-invalid" | "data-invalid"
                | "asset-invalid" | "issued-at-missing" => 400,
                _ => return Err(error("protocol")),
            };
            if problem.status != status.as_u16()
                || problem.status != expected_status
                || problem.title != slug
                || problem.type_uri != format!("https://render.registrystack.org/problems/{slug}")
                || problem.detail.is_empty()
                || problem.detail.len() > 2048
                || problem.trace_id != trace
                || pointers.len() > 32
                || pointers.iter().any(|pointer| {
                    pointer.len() > 1024 || (!pointer.is_empty() && !pointer.starts_with('/'))
                })
            {
                return Err(error("protocol"));
            }
            return Err(RenderClientError {
                kind: "problem",
                outcome_unknown: false,
                transport_kind: None,
                status: Some(problem.status),
                code: Some(problem.code),
                trace_id: Some(trace.as_str().to_owned()),
            });
        }
        if status != reqwest::StatusCode::OK {
            return Err(error("protocol"));
        }
        if let Some(key) = idempotency_key {
            if echoed != [Some(key.to_owned())] {
                return Err(error("protocol"));
            }
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Render,
    Seal,
}
impl Route {
    fn segment(self) -> &'static str {
        match self {
            Self::Render => "render",
            Self::Seal => "seal",
        }
    }
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_version_and_warnings(document_type: &str, version: &str, warnings: &[String]) -> bool {
    version
        .strip_prefix(&format!("{document_type} v"))
        .and_then(|number| number.parse::<u32>().ok())
        .is_some_and(|number| version == format!("{document_type} v{number}"))
        && warnings.len() <= 256
        && warnings.iter().all(|warning| warning.len() <= 2048)
}

/// Whether `document_sha256` is the SHA-256 of a prefix of `pdf` that ends at
/// a `%%EOF` marker, optionally followed by its end-of-line. Found by byte
/// search; the PDF is not parsed. A prefix equal to the whole file is not a
/// first revision.
fn first_revision_matches(pdf: &[u8], document_sha256: &str) -> bool {
    const MARKER: &[u8] = b"%%EOF";
    // A real file has a handful of markers; bound the hashing work.
    const MAXIMUM_CANDIDATES: usize = 64;
    let mut candidates = 0;
    for (start, window) in pdf.windows(MARKER.len()).enumerate() {
        if window != MARKER {
            continue;
        }
        candidates += 1;
        if candidates > MAXIMUM_CANDIDATES {
            return false;
        }
        let marker_end = start + MARKER.len();
        let eol = match pdf[marker_end..] {
            [b'\r', b'\n', ..] => 2,
            [b'\r' | b'\n', ..] => 1,
            _ => 0,
        };
        for end in [marker_end, marker_end + eol] {
            if end < pdf.len() && hex::encode(Sha256::digest(&pdf[..end])) == document_sha256 {
                return true;
            }
            if eol == 0 {
                break;
            }
        }
    }
    false
}

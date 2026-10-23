// SPDX-License-Identifier: Apache-2.0
//! Thin client for the Render HTTP adapter. Rendering is one exchange; a
//! correlation key is never treated as an idempotency or deduplication promise.
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderedDocument {
    pub pdf_base64: String,
    pub pdf_sha256: String,
    pub data_sha256: String,
    pub document_version: String,
    pub warnings: Vec<String>,
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
        let url = self
            .base_url
            .join(&format!("v1/render/{document_type}"))
            .map_err(|_| error("invalid-request"))?;
        let response = self
            .http
            .post(url)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
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
        let document: RenderedDocument =
            serde_json::from_value(value).map_err(|_| error("protocol"))?;
        let pdf = base64::engine::general_purpose::STANDARD
            .decode(&document.pdf_base64)
            .map_err(|_| error("protocol"))?;
        let digest = |text: &str| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !pdf.starts_with(b"%PDF-")
            || !digest(&document.pdf_sha256)
            || !digest(&document.data_sha256)
            || hex::encode(Sha256::digest(&pdf)) != document.pdf_sha256
            || document
                .document_version
                .strip_prefix(&format!("{document_type} v"))
                .and_then(|version| version.parse::<u32>().ok())
                .is_none_or(|version| {
                    document.document_version != format!("{document_type} v{version}")
                })
            || document.warnings.len() > 256
            || document.warnings.iter().any(|warning| warning.len() > 2048)
        {
            return Err(error("protocol"));
        }
        Ok(document)
    }
}

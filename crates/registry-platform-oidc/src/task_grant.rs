// SPDX-License-Identifier: Apache-2.0
//! Fresh, bounded exact-status checks for immutable task authorizations.
use crate::{GrantBounds, GrantClaims};
use registry_platform_httputil::{
    client::{build_client, OutboundOptions, PrivateKeyJwt, ServiceBaseUrl, TokenProvider},
    read_bounded, validate_response_headers,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};
use thiserror::Error;
use uuid::Uuid;
mod config;
pub use config::{TaskGrantStatusEndpoint, TaskGrantStatusRegistry};

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatusBinding {
    grant_id: String,
    source_issuer: String,
    principal: String,
    client: String,
    resource: String,
    purpose: String,
    bounds: GrantBounds,
    subjects: BTreeMap<String, Value>,
    expires_at: u64,
}
impl fmt::Debug for TaskGrantStatusBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskGrantStatusBinding(<redacted>)")
    }
}
impl TaskGrantStatusBinding {
    /// The product must first verify the credential, client/resource context,
    /// and its own supported bounds. No request body can create this binding.
    pub fn from_verified(
        grant: &GrantClaims,
        subjects: BTreeMap<String, Value>,
    ) -> Result<Self, TaskGrantError> {
        let binding = Self {
            grant_id: grant.id().into(),
            source_issuer: grant.source_issuer().into(),
            principal: grant.principal().into(),
            client: grant.client().into(),
            resource: grant.resource().into(),
            purpose: grant.purpose().into(),
            bounds: grant.bounds().clone(),
            subjects,
            expires_at: grant.exp(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), TaskGrantError> {
        if Uuid::parse_str(&self.grant_id).is_err()
            || [
                &self.source_issuer,
                &self.principal,
                &self.client,
                &self.resource,
                &self.purpose,
            ]
            .iter()
            .any(|value| {
                value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
            || self.subjects.is_empty()
            || self.subjects.len() > 32
            || self.subjects.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 128
                    || key.chars().any(char::is_control)
                    || match value {
                        Value::String(value) => {
                            value.is_empty()
                                || value.len() > 512
                                || value.chars().any(char::is_control)
                        }
                        Value::Bool(_) => false,
                        Value::Number(value) => {
                            value.as_i64().is_none() && value.as_u64().is_none()
                        }
                        _ => true,
                    }
            })
        {
            return Err(TaskGrantError::Refused);
        }
        Ok(())
    }
    fn is_current(&self) -> bool {
        u64::try_from(chrono::Utc::now().timestamp()).is_ok_and(|now| now < self.expires_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum TaskGrantError {
    #[error("task authority was refused")]
    Refused,
    #[error("task authority status is unavailable")]
    Unavailable,
    #[error("task authority status configuration is invalid")]
    Configuration,
}

/// A status route appended to the service base's path, parsed from a template
/// that starts with `/` and has exactly one whole `{grantId}` segment. Every
/// other segment is made of RFC 3986 unreserved characters, so the route
/// cannot add a query, a fragment, an encoded character, or a dot segment.
#[derive(Clone, Debug)]
struct StatusPath(Vec<Option<String>>);
impl StatusPath {
    const GRANT_ID: &'static str = "{grantId}";

    fn parse(template: &str) -> Result<Self, TaskGrantError> {
        let segments = template
            .strip_prefix('/')
            .filter(|_| template.len() <= 256)
            .ok_or(TaskGrantError::Configuration)?
            .split('/')
            .map(|segment| match segment {
                Self::GRANT_ID => Ok(None),
                "." | ".." => Err(TaskGrantError::Configuration),
                literal
                    if !literal.is_empty()
                        && literal.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
                        }) =>
                {
                    Ok(Some(literal.to_owned()))
                }
                _ => Err(TaskGrantError::Configuration),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if segments.iter().filter(|segment| segment.is_none()).count() != 1 {
            return Err(TaskGrantError::Configuration);
        }
        Ok(Self(segments))
    }

    fn segments<'a>(&'a self, grant_id: &'a str) -> Vec<&'a str> {
        self.0
            .iter()
            .map(|segment| segment.as_deref().unwrap_or(grant_id))
            .collect()
    }
}

pub struct TaskGrantStatusClient {
    source_issuer: String,
    resource: String,
    base: ServiceBaseUrl,
    status_path: StatusPath,
    http: reqwest::Client,
    token: Arc<PrivateKeyJwt>,
}
impl fmt::Debug for TaskGrantStatusClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskGrantStatusClient(<configured>)")
    }
}
impl TaskGrantStatusClient {
    /// `status_path` is the status route appended to `base`'s path: it starts
    /// with `/` and has exactly one whole `{grantId}` segment.
    pub fn new(
        source_issuer: String,
        resource: String,
        base: reqwest::Url,
        status_path: &str,
        token: Arc<PrivateKeyJwt>,
        trusted_roots: Option<&[u8]>,
    ) -> Result<Self, TaskGrantError> {
        if !registry_platform_httputil::valid_resource_uri(&source_issuer)
            || !registry_platform_httputil::valid_resource_uri(&resource)
        {
            return Err(TaskGrantError::Configuration);
        }
        let base = ServiceBaseUrl::new(base).map_err(|_| TaskGrantError::Configuration)?;
        let status_path = StatusPath::parse(status_path)?;
        let http = build_client(OutboundOptions {
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(3),
            user_agent: Some("registry-task-status"),
            trusted_root_certificates: trusted_roots,
        })
        .map_err(|_| TaskGrantError::Configuration)?;
        Ok(Self {
            source_issuer,
            resource,
            base,
            status_path,
            http,
            token,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusResponse {
    active: bool,
    #[serde(default)]
    grant: Option<TaskGrantStatusBinding>,
}
impl TaskGrantStatusClient {
    /// Perform one fresh observation. The caller supplies only a verified immutable
    /// context, not a request body. Positive status is never cached. The complete
    /// attempt, including acquisition of the service credential, is bounded.
    pub async fn check(&self, binding: &TaskGrantStatusBinding) -> Result<(), TaskGrantError> {
        tokio::time::timeout(Duration::from_secs(10), async {
            binding.validate()?;
            if !binding.is_current()
                || binding.source_issuer != self.source_issuer
                || binding.resource != self.resource
            {
                return Err(TaskGrantError::Refused);
            }
            let token = self
                .token
                .bearer_token()
                .await
                .map_err(|_| TaskGrantError::Unavailable)?;
            let url = registry_platform_httputil::url::append_path_segments(
                self.base.as_url(),
                &self.status_path.segments(&binding.grant_id),
            )
            .map_err(|_| TaskGrantError::Configuration)?;
            let response = self
                .http
                .get(url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    token.authorization_header_value(),
                )
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|_| TaskGrantError::Unavailable)?;
            validate_response_headers(response.headers())
                .map_err(|_| TaskGrantError::Unavailable)?;
            // A concealed or absent grant is a refusal. Rejected status-service
            // credentials do not establish inactive authority and remain unavailable.
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(TaskGrantError::Refused);
            }
            if response.status() != reqwest::StatusCode::OK
                || response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(';').next())
                    .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
            {
                return Err(TaskGrantError::Unavailable);
            }
            let bytes = read_bounded(response, 64 * 1024)
                .await
                .map_err(|_| TaskGrantError::Unavailable)?;
            let json = registry_platform_crypto::parse_json_strict(&bytes)
                .map_err(|_| TaskGrantError::Unavailable)?;
            let status: StatusResponse =
                serde_json::from_value(json).map_err(|_| TaskGrantError::Unavailable)?;
            if !status.active || status.grant.as_ref() != Some(binding) || !binding.is_current() {
                return Err(TaskGrantError::Refused);
            }
            Ok(())
        })
        .await
        .map_err(|_| TaskGrantError::Unavailable)?
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: Apache-2.0
//! Immutable task authority retained separately from a later human reviewer.
use registry_platform_httputil::{
    client::{build_client, OutboundOptions, PrivateKeyJwt, ServiceBaseUrl, TokenProvider},
    read_bounded, validate_response_headers,
};
use registry_platform_oidc::{GrantBounds, GrantClaims};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};
use thiserror::Error;
use uuid::Uuid;
mod config;
pub use config::{TaskGrantStatusConfig, TaskGrantStatusRegistry};

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantBinding {
    grant_id: String,
    authority: String,
    source_issuer: String,
    principal: String,
    client: String,
    resource: String,
    purpose: String,
    bounds: GrantBounds,
    subjects: BTreeMap<String, Value>,
    expires_at: u64,
}
impl fmt::Debug for TaskGrantBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskGrantBinding(<redacted>)")
    }
}
impl TaskGrantBinding {
    /// The caller must first verify the JWT, grant context, and selected profile.
    /// Preserve all immutable identity members, while granting only the selected
    /// profile's own mapped permissions.
    pub(crate) fn from_verified(
        grant: &GrantClaims,
        subjects: BTreeMap<String, Value>,
    ) -> Result<Self, TaskGrantError> {
        let binding = Self {
            grant_id: grant.id().into(),
            authority: grant.authority().into(),
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
    pub(crate) fn validate(&self) -> Result<(), TaskGrantError> {
        if Uuid::parse_str(&self.grant_id).is_err()
            || self.bounds.breg_permissions().is_none()
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
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
    pub fn authority(&self) -> &str {
        &self.authority
    }
    pub fn source_issuer(&self) -> &str {
        &self.source_issuer
    }
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn client(&self) -> &str {
        &self.client
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    pub fn bounds(&self) -> &GrantBounds {
        &self.bounds
    }
    pub fn subjects(&self) -> &BTreeMap<String, Value> {
        &self.subjects
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub(crate) fn is_current(&self) -> bool {
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

pub trait TaskGrantStatusChecker: Send + Sync {
    /// Each invocation must perform a fresh check. Never cache positive status.
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>;
}

pub struct TaskGrantStatusClient {
    authority: String,
    source_issuer: String,
    resource: String,
    base: ServiceBaseUrl,
    http: reqwest::Client,
    token: Arc<PrivateKeyJwt>,
}
impl fmt::Debug for TaskGrantStatusClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskGrantStatusClient(<configured>)")
    }
}
impl TaskGrantStatusClient {
    pub fn new(
        authority: String,
        source_issuer: String,
        resource: String,
        base: reqwest::Url,
        token: Arc<PrivateKeyJwt>,
        trusted_roots: Option<&[u8]>,
    ) -> Result<Self, TaskGrantError> {
        if authority.is_empty()
            || authority.len() > 512
            || !registry_platform_httputil::valid_resource_uri(&source_issuer)
            || !registry_platform_httputil::valid_resource_uri(&resource)
        {
            return Err(TaskGrantError::Configuration);
        }
        let base = ServiceBaseUrl::new(base).map_err(|_| TaskGrantError::Configuration)?;
        let http = build_client(OutboundOptions {
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(3),
            user_agent: Some("registry-breg-task-status"),
            trusted_root_certificates: trusted_roots,
        })
        .map_err(|_| TaskGrantError::Configuration)?;
        Ok(Self {
            authority,
            source_issuer,
            resource,
            base,
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
    grant: Option<TaskGrantBinding>,
}
impl TaskGrantStatusChecker for TaskGrantStatusClient {
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>
    {
        Box::pin(async move {
            binding.validate()?;
            if !binding.is_current()
                || binding.authority != self.authority
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
                &["v1", "task-grants", &binding.grant_id, "status"],
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
            if matches!(response.status().as_u16(), 401 | 403 | 404) {
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
    }
}

#[cfg(test)]
mod tests;

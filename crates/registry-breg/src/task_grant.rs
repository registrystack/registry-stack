// SPDX-License-Identifier: Apache-2.0
//! Immutable task authority retained separately from a later human reviewer.
use registry_platform_httputil::client::PrivateKeyJwt;
pub use registry_platform_oidc::task_grant::TaskGrantError;
use registry_platform_oidc::{GrantBounds, GrantClaims};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, sync::Arc};
use uuid::Uuid;
mod config;
pub use config::{TaskGrantStatusConfig, TaskGrantStatusRegistry};

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantBinding {
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

pub trait TaskGrantStatusChecker: Send + Sync {
    /// Each invocation must perform a fresh check. Never cache positive status.
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>;
}

/// BReg retains its product-specific binding policy around the shared transport.
pub struct TaskGrantStatusClient(registry_platform_oidc::task_grant::TaskGrantStatusClient);
impl fmt::Debug for TaskGrantStatusClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskGrantStatusClient(<configured>)")
    }
}
impl TaskGrantStatusClient {
    pub fn new(
        source_issuer: String,
        resource: String,
        base: reqwest::Url,
        token: Arc<PrivateKeyJwt>,
        trusted_roots: Option<&[u8]>,
    ) -> Result<Self, TaskGrantError> {
        registry_platform_oidc::task_grant::TaskGrantStatusClient::new(
            source_issuer,
            resource,
            base,
            token,
            trusted_roots,
        )
        .map(Self)
    }
}
impl TaskGrantStatusChecker for TaskGrantStatusClient {
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>
    {
        Box::pin(async move { self.0.check(&binding.status_binding()?).await })
    }
}
impl TaskGrantBinding {
    fn status_binding(
        &self,
    ) -> Result<registry_platform_oidc::task_grant::TaskGrantStatusBinding, TaskGrantError> {
        self.validate()?;
        // Retain the existing persisted BReg shape and product-specific bounds
        // check; the shared transport consumes the identical closed wire model.
        serde_json::from_value(serde_json::to_value(self).map_err(|_| TaskGrantError::Refused)?)
            .map_err(|_| TaskGrantError::Refused)
    }
}

#[cfg(test)]
mod tests;

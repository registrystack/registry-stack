// SPDX-License-Identifier: Apache-2.0
//! Credential status store configuration.

use super::*;

pub const CREDENTIAL_STATUS_VALID: &str = "valid";
pub const CREDENTIAL_STATUS_SUSPENDED: &str = "suspended";
pub const CREDENTIAL_STATUS_REVOKED: &str = "revoked";
pub const CREDENTIAL_STATUS_EXPIRED: &str = "expired";
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialStatusConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: String,
    #[serde(default = "default_credential_status_retention_seconds")]
    pub retention_seconds: u64,
}

impl Default for CredentialStatusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            retention_seconds: default_credential_status_retention_seconds(),
        }
    }
}

impl CredentialStatusConfig {
    pub(super) fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        validate_credential_status_http_url("credential_status.base_url", &self.base_url)?;
        if self.retention_seconds == 0 {
            return invalid_credential_status(
                "credential_status.retention_seconds must be greater than zero",
            );
        }
        Ok(())
    }
}

pub(super) fn credential_status_config_is_default(config: &CredentialStatusConfig) -> bool {
    config == &CredentialStatusConfig::default()
}

pub(super) const fn default_credential_status_retention_seconds() -> u64 {
    86_400
}

pub(super) fn validate_credential_status_non_empty(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_credential_status(format!("{field} must not be empty"));
    }
    Ok(())
}

pub(super) fn validate_credential_status_http_url(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    validate_credential_status_non_empty(field, value)?;
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return invalid_credential_status(format!("{field} must be an HTTP or HTTPS URL"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return invalid_credential_status(format!("{field} must include a valid host"));
    }
    Ok(())
}

pub(super) fn invalid_credential_status<T>(
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidCredentialStatusConfig {
        reason: reason.into(),
    })
}

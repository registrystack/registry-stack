// SPDX-License-Identifier: Apache-2.0
//! HTTP listener configuration.

use super::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryHttpConfig {
    #[serde(default = "default_bind_addr")]
    pub bind: SocketAddr,
    #[serde(
        default = "default_openapi_requires_auth",
        skip_serializing_if = "openapi_requires_auth_is_default"
    )]
    pub openapi_requires_auth: bool,
    #[serde(default, skip_serializing_if = "admin_listener_config_is_default")]
    pub admin_listener: RegistryNotaryAdminListenerConfig,
    #[serde(default)]
    pub cors: RegistryNotaryCorsConfig,
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,
    #[serde(default = "default_request_body_timeout", with = "humantime_serde")]
    pub request_body_timeout: Duration,
    #[serde(
        default = "default_http1_header_read_timeout",
        with = "humantime_serde"
    )]
    pub http1_header_read_timeout: Duration,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxy_ips: Vec<IpAddr>,
}

impl Default for RegistryNotaryHttpConfig {
    fn default() -> Self {
        Self {
            bind: default_bind_addr(),
            openapi_requires_auth: default_openapi_requires_auth(),
            admin_listener: RegistryNotaryAdminListenerConfig::default(),
            cors: RegistryNotaryCorsConfig::default(),
            request_timeout: default_request_timeout(),
            request_body_timeout: default_request_body_timeout(),
            http1_header_read_timeout: default_http1_header_read_timeout(),
            max_connections: default_max_connections(),
            trusted_proxy_ips: Vec::new(),
        }
    }
}

impl RegistryNotaryHttpConfig {
    pub(super) fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.request_timeout.is_zero()
            || self.request_body_timeout.is_zero()
            || self.http1_header_read_timeout.is_zero()
            || self.max_connections == 0
        {
            return Err(EvidenceConfigError::InvalidServerConfig {
                reason:
                    "server timeouts must be non-zero and max_connections must be greater than zero"
                        .to_string(),
            });
        }
        Ok(())
    }
}

pub(super) fn default_bind_addr() -> SocketAddr {
    // SAFETY: the literal is a valid loopback socket address.
    "127.0.0.1:8081"
        .parse()
        .expect("default bind address is valid")
}

pub(super) fn default_openapi_requires_auth() -> bool {
    true
}

pub(super) fn openapi_requires_auth_is_default(value: &bool) -> bool {
    *value == default_openapi_requires_auth()
}

pub(super) fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

pub(super) fn default_request_body_timeout() -> Duration {
    Duration::from_secs(10)
}

pub(super) fn default_http1_header_read_timeout() -> Duration {
    Duration::from_secs(10)
}

pub(super) fn default_max_connections() -> usize {
    1024
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryNotaryAdminListenerMode {
    SharedWithPublic,
    Dedicated,
    #[default]
    Disabled,
}

impl RegistryNotaryAdminListenerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedWithPublic => "shared_with_public",
            Self::Dedicated => "dedicated",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryAdminListenerConfig {
    #[serde(default, skip_serializing_if = "admin_listener_mode_is_default")]
    pub mode: RegistryNotaryAdminListenerMode,
    #[serde(default = "default_admin_bind_addr")]
    pub bind: SocketAddr,
}

impl RegistryNotaryAdminListenerConfig {
    pub(super) fn validate(
        &self,
        public_bind: SocketAddr,
        governed_config_enabled: bool,
    ) -> Result<(), EvidenceConfigError> {
        if governed_config_enabled && self.mode != RegistryNotaryAdminListenerMode::Dedicated {
            return Err(EvidenceConfigError::InvalidServerConfig {
                reason: "config_trust requires server.admin_listener.mode = dedicated".to_string(),
            });
        }
        if self.mode == RegistryNotaryAdminListenerMode::Dedicated && self.bind == public_bind {
            return Err(EvidenceConfigError::InvalidServerConfig {
                reason: "server.admin_listener.bind must differ from server.bind in dedicated mode"
                    .to_string(),
            });
        }
        Ok(())
    }
}

impl Default for RegistryNotaryAdminListenerConfig {
    fn default() -> Self {
        Self {
            mode: RegistryNotaryAdminListenerMode::Disabled,
            bind: default_admin_bind_addr(),
        }
    }
}

pub(super) fn default_admin_bind_addr() -> SocketAddr {
    // SAFETY: the literal is a valid loopback socket address.
    "127.0.0.1:8082"
        .parse()
        .expect("default admin bind address is valid")
}

pub(super) fn admin_listener_config_is_default(config: &RegistryNotaryAdminListenerConfig) -> bool {
    config == &RegistryNotaryAdminListenerConfig::default()
}

pub(super) fn admin_listener_mode_is_default(mode: &RegistryNotaryAdminListenerMode) -> bool {
    mode == &RegistryNotaryAdminListenerMode::default()
}

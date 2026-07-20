// SPDX-License-Identifier: Apache-2.0
//! Registry Notary correctness-state storage configuration.

use super::*;

pub const STATE_STORAGE_IN_MEMORY: &str = "in_memory";
pub const STATE_STORAGE_POSTGRESQL: &str = "postgresql";
pub const STATE_POSTGRESQL_MAX_CONNECTIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    #[serde(default = "default_state_storage")]
    pub storage: String,
    #[serde(default, skip_serializing_if = "state_postgresql_config_is_default")]
    pub postgresql: StatePostgresqlConfig,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            storage: default_state_storage(),
            postgresql: StatePostgresqlConfig::default(),
        }
    }
}

impl StateConfig {
    pub(super) fn validate(
        &self,
        deployment: &DeploymentConfig,
        preauthorization_enabled: bool,
    ) -> Result<(), EvidenceConfigError> {
        match self.storage.as_str() {
            STATE_STORAGE_POSTGRESQL => {
                validate_state_non_empty("state.postgresql.url_env", &self.postgresql.url_env)?;
                if self.postgresql.connect_timeout_ms == 0 {
                    return invalid_state(
                        "state.postgresql.connect_timeout_ms must be greater than zero",
                    );
                }
                if self.postgresql.operation_timeout_ms == 0 {
                    return invalid_state(
                        "state.postgresql.operation_timeout_ms must be greater than zero",
                    );
                }
                if !(1..=STATE_POSTGRESQL_MAX_CONNECTIONS)
                    .contains(&self.postgresql.max_connections)
                {
                    return invalid_state(
                        "state.postgresql.max_connections must be between 1 and 256",
                    );
                }
                if self
                    .postgresql
                    .root_certificate_path
                    .as_ref()
                    .is_some_and(|path| path.as_os_str().is_empty())
                {
                    return invalid_state(
                        "state.postgresql.root_certificate_path must not be empty when set",
                    );
                }
                if preauthorization_enabled {
                    validate_state_non_empty(
                        "state.postgresql.sensitive_state_key_env",
                        &self.postgresql.sensitive_state_key_env,
                    )?;
                }
                Ok(())
            }
            STATE_STORAGE_IN_MEMORY => {
                if deployment.profile != Some(crate::deployment::DeploymentProfile::Local) {
                    return invalid_state(
                        "state.storage = in_memory requires deployment.profile = local",
                    );
                }
                if deployment.multi_instance {
                    return invalid_state(
                        "state.storage = in_memory requires deployment.multi_instance = false",
                    );
                }
                Ok(())
            }
            _ => invalid_state("state.storage must be postgresql or in_memory"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatePostgresqlConfig {
    #[serde(default = "default_state_postgresql_url_env")]
    pub url_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_certificate_path: Option<PathBuf>,
    #[serde(default = "default_state_postgresql_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_state_postgresql_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
    #[serde(default = "default_state_postgresql_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_sensitive_state_key_env")]
    pub sensitive_state_key_env: String,
}

impl Default for StatePostgresqlConfig {
    fn default() -> Self {
        Self {
            url_env: default_state_postgresql_url_env(),
            root_certificate_path: None,
            connect_timeout_ms: default_state_postgresql_connect_timeout_ms(),
            operation_timeout_ms: default_state_postgresql_operation_timeout_ms(),
            max_connections: default_state_postgresql_max_connections(),
            sensitive_state_key_env: default_sensitive_state_key_env(),
        }
    }
}

pub(super) fn state_config_is_default(config: &StateConfig) -> bool {
    config == &StateConfig::default()
}

pub(super) fn state_postgresql_config_is_default(config: &StatePostgresqlConfig) -> bool {
    config == &StatePostgresqlConfig::default()
}

pub(super) fn default_state_storage() -> String {
    STATE_STORAGE_POSTGRESQL.to_string()
}

pub(super) fn default_state_postgresql_url_env() -> String {
    "REGISTRY_NOTARY_POSTGRES_URL".to_string()
}

pub(super) const fn default_state_postgresql_connect_timeout_ms() -> u64 {
    5_000
}

pub(super) const fn default_state_postgresql_operation_timeout_ms() -> u64 {
    2_000
}

pub(super) const fn default_state_postgresql_max_connections() -> usize {
    16
}

pub(super) fn default_sensitive_state_key_env() -> String {
    "REGISTRY_NOTARY_SENSITIVE_STATE_KEY".to_string()
}

fn validate_state_non_empty(field: &str, value: &str) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_state(format!("{field} must not be empty"));
    }
    Ok(())
}

fn invalid_state<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidStateConfig {
        reason: reason.into(),
    })
}

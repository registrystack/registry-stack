// SPDX-License-Identifier: Apache-2.0
//! Replay store configuration.

use super::*;

pub const REPLAY_STORAGE_IN_MEMORY: &str = "in_memory";
pub const REPLAY_STORAGE_REDIS: &str = "redis";
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConfig {
    #[serde(default = "default_replay_storage")]
    pub storage: String,
    #[serde(default)]
    pub redis: ReplayRedisConfig,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            storage: default_replay_storage(),
            redis: ReplayRedisConfig::default(),
        }
    }
}

impl ReplayConfig {
    pub(super) fn validate(&self) -> Result<(), EvidenceConfigError> {
        match self.storage.as_str() {
            REPLAY_STORAGE_IN_MEMORY => Ok(()),
            REPLAY_STORAGE_REDIS => {
                validate_replay_non_empty("replay.redis.url_env", &self.redis.url_env)?;
                validate_replay_non_empty("replay.redis.key_prefix", &self.redis.key_prefix)?;
                if self.redis.connect_timeout_ms == 0 {
                    return invalid_replay(
                        "replay.redis.connect_timeout_ms must be greater than zero",
                    );
                }
                if self.redis.operation_timeout_ms == 0 {
                    return invalid_replay(
                        "replay.redis.operation_timeout_ms must be greater than zero",
                    );
                }
                Ok(())
            }
            _ => invalid_replay("replay.storage must be in_memory or redis"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRedisConfig {
    #[serde(default)]
    pub url_env: String,
    #[serde(default = "default_replay_redis_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_replay_redis_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_replay_redis_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
}

impl Default for ReplayRedisConfig {
    fn default() -> Self {
        Self {
            url_env: String::new(),
            key_prefix: default_replay_redis_key_prefix(),
            connect_timeout_ms: default_replay_redis_connect_timeout_ms(),
            operation_timeout_ms: default_replay_redis_operation_timeout_ms(),
        }
    }
}

pub(super) fn replay_config_is_default(config: &ReplayConfig) -> bool {
    config == &ReplayConfig::default()
}

pub(super) fn default_replay_storage() -> String {
    REPLAY_STORAGE_IN_MEMORY.to_string()
}

pub(super) fn default_replay_redis_key_prefix() -> String {
    "registry-notary".to_string()
}

pub(super) const fn default_replay_redis_connect_timeout_ms() -> u64 {
    1000
}

pub(super) const fn default_replay_redis_operation_timeout_ms() -> u64 {
    500
}

pub(super) fn validate_replay_non_empty(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_replay(format!("{field} must not be empty"));
    }
    Ok(())
}

pub(super) fn invalid_replay<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidReplayConfig {
        reason: reason.into(),
    })
}

// SPDX-License-Identifier: Apache-2.0
//! CEL worker configuration.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryCelConfig {
    #[serde(default = "default_cel_mode")]
    pub mode: String,
    #[serde(default = "default_cel_worker_count")]
    pub worker_count: usize,
    #[serde(default = "default_cel_eval_timeout_ms")]
    pub eval_timeout_ms: u64,
    #[serde(default)]
    pub allow_regex: bool,
    #[serde(default = "default_cel_max_expression_bytes")]
    pub max_expression_bytes: usize,
    #[serde(default = "default_cel_max_binding_json_bytes")]
    pub max_binding_json_bytes: usize,
    #[serde(default = "default_cel_max_result_json_bytes")]
    pub max_result_json_bytes: usize,
    #[serde(default = "default_cel_max_string_bytes")]
    pub max_string_bytes: usize,
    #[serde(default = "default_cel_max_list_items")]
    pub max_list_items: usize,
    #[serde(default = "default_cel_max_object_depth")]
    pub max_object_depth: usize,
    #[serde(default = "default_cel_max_object_keys")]
    pub max_object_keys: usize,
    #[serde(default = "default_cel_worker_memory_bytes")]
    pub worker_memory_bytes: u64,
    #[serde(default = "default_cel_worker_stderr_bytes")]
    pub worker_stderr_bytes: usize,
}

impl Default for RegistryNotaryCelConfig {
    fn default() -> Self {
        Self {
            mode: default_cel_mode(),
            worker_count: default_cel_worker_count(),
            eval_timeout_ms: default_cel_eval_timeout_ms(),
            allow_regex: false,
            max_expression_bytes: default_cel_max_expression_bytes(),
            max_binding_json_bytes: default_cel_max_binding_json_bytes(),
            max_result_json_bytes: default_cel_max_result_json_bytes(),
            max_string_bytes: default_cel_max_string_bytes(),
            max_list_items: default_cel_max_list_items(),
            max_object_depth: default_cel_max_object_depth(),
            max_object_keys: default_cel_max_object_keys(),
            worker_memory_bytes: default_cel_worker_memory_bytes(),
            worker_stderr_bytes: default_cel_worker_stderr_bytes(),
        }
    }
}

impl RegistryNotaryCelConfig {
    pub(super) fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.mode != "worker" && self.mode != "disabled" {
            return invalid_cel("cel.mode must be worker or disabled");
        }
        if self.worker_count == 0 || self.worker_count > 16 {
            return invalid_cel("cel.worker_count must be between 1 and 16");
        }
        if self.eval_timeout_ms == 0 || self.eval_timeout_ms > 30_000 {
            return invalid_cel("cel.eval_timeout_ms must be between 1 and 30000");
        }
        if self.max_expression_bytes == 0 || self.max_expression_bytes > 256 * 1024 {
            return invalid_cel("cel.max_expression_bytes must be between 1 and 262144");
        }
        if self.max_binding_json_bytes == 0 || self.max_binding_json_bytes > 1024 * 1024 {
            return invalid_cel("cel.max_binding_json_bytes must be between 1 and 1048576");
        }
        if self.max_result_json_bytes == 0 || self.max_result_json_bytes > 1024 * 1024 {
            return invalid_cel("cel.max_result_json_bytes must be between 1 and 1048576");
        }
        if self.max_string_bytes == 0 || self.max_string_bytes > 256 * 1024 {
            return invalid_cel("cel.max_string_bytes must be between 1 and 262144");
        }
        if self.max_list_items == 0 || self.max_list_items > 100_000 {
            return invalid_cel("cel.max_list_items must be between 1 and 100000");
        }
        if self.max_object_depth == 0 || self.max_object_depth > 64 {
            return invalid_cel("cel.max_object_depth must be between 1 and 64");
        }
        if self.max_object_keys == 0 || self.max_object_keys > 2048 {
            return invalid_cel("cel.max_object_keys must be between 1 and 2048");
        }
        if self.worker_memory_bytes < 32 * 1024 * 1024
            || self.worker_memory_bytes > 1024 * 1024 * 1024
        {
            return invalid_cel("cel.worker_memory_bytes must be between 33554432 and 1073741824");
        }
        if self.worker_stderr_bytes == 0 || self.worker_stderr_bytes > 64 * 1024 {
            return invalid_cel("cel.worker_stderr_bytes must be between 1 and 65536");
        }
        Ok(())
    }
}

pub(super) fn registry_notary_cel_config_is_default(config: &RegistryNotaryCelConfig) -> bool {
    config == &RegistryNotaryCelConfig::default()
}

pub(super) fn invalid_cel<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidCelConfig {
        reason: reason.into(),
    })
}

pub(super) fn default_cel_mode() -> String {
    "worker".to_string()
}

pub(super) const fn default_cel_worker_count() -> usize {
    2
}

pub(super) const fn default_cel_eval_timeout_ms() -> u64 {
    2_000
}

pub(super) const fn default_cel_max_expression_bytes() -> usize {
    8 * 1024
}

pub(super) const fn default_cel_max_binding_json_bytes() -> usize {
    64 * 1024
}

pub(super) const fn default_cel_max_result_json_bytes() -> usize {
    16 * 1024
}

pub(super) const fn default_cel_max_string_bytes() -> usize {
    16 * 1024
}

pub(super) const fn default_cel_max_list_items() -> usize {
    1024
}

pub(super) const fn default_cel_max_object_depth() -> usize {
    16
}

pub(super) const fn default_cel_max_object_keys() -> usize {
    256
}

pub(super) const fn default_cel_worker_memory_bytes() -> u64 {
    128 * 1024 * 1024
}

pub(super) const fn default_cel_worker_stderr_bytes() -> usize {
    1024
}

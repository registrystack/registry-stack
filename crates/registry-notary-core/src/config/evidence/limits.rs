// SPDX-License-Identifier: Apache-2.0
//! Evaluation concurrency and machine quota configuration.

use super::*;

/// Per-request cap on concurrently evaluated subjects.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyConfig {
    #[serde(default = "default_concurrency_subjects")]
    pub subjects: usize,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            subjects: default_concurrency_subjects(),
        }
    }
}

impl ConcurrencyConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.subjects < 1 {
            return Err(EvidenceConfigError::InvalidConcurrency);
        }
        Ok(())
    }
}

const fn default_concurrency_subjects() -> usize {
    16
}

/// Per-principal quota for machine `evaluate`/`batch_evaluate` traffic.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineQuotaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_machine_quota_subjects_per_minute")]
    pub subjects_per_minute: u32,
}

impl Default for MachineQuotaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            subjects_per_minute: default_machine_quota_subjects_per_minute(),
        }
    }
}

impl MachineQuotaConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.enabled && self.subjects_per_minute == 0 {
            return Err(EvidenceConfigError::InvalidMachineQuotaConfig {
                reason: "subjects_per_minute must be greater than zero when enabled".to_string(),
            });
        }
        Ok(())
    }
}

const fn default_machine_quota_subjects_per_minute() -> u32 {
    6000
}

// SPDX-License-Identifier: Apache-2.0
//! Shared parsing helpers for signed config bundle verification.

use registry_notary_core::{
    deprecated_config_fields, ConfigTrustConfig, StandaloneRegistryNotaryConfig,
};
use registry_platform_config::reject_deprecated_config_fields;
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct ConfigGovernanceContext {
    pub(crate) instance_id: String,
    pub(crate) environment: String,
    pub(crate) config_trust: Option<ConfigTrustConfig>,
}

impl ConfigGovernanceContext {
    #[must_use]
    pub fn from_config(config: &StandaloneRegistryNotaryConfig) -> Self {
        Self {
            instance_id: config.instance.id.clone(),
            environment: config.instance.environment.clone(),
            config_trust: config.config_trust.clone(),
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    #[must_use]
    pub fn config_trust(&self) -> Option<&ConfigTrustConfig> {
        self.config_trust.as_ref()
    }
}

impl Default for ConfigGovernanceContext {
    fn default() -> Self {
        Self {
            instance_id: "registry-notary-standalone".to_string(),
            environment: "development".to_string(),
            config_trust: None,
        }
    }
}

pub fn parse_candidate_config(config_yaml: &str) -> Result<StandaloneRegistryNotaryConfig, String> {
    let value: Value = serde_norway::from_str(config_yaml)
        .map_err(|error| format!("candidate config could not be parsed: {error}"))?;
    reject_deprecated_config_fields(&value, &deprecated_config_fields())
        .map_err(|error| error.to_string())?;
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(config_yaml)
        .map_err(|error| format!("candidate config could not be parsed: {error}"))?;
    config
        .validate()
        .map_err(|error| format!("candidate config did not validate: {error}"))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_candidate_config_names_deprecated_field_replacements() {
        let err = parse_candidate_config("audit:\n  max_size_bytes: 10485760\n")
            .expect_err("deprecated candidate field is rejected");

        assert!(err.contains("audit.max_size_mb"), "unexpected: {err}");
    }
}

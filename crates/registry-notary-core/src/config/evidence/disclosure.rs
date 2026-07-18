// SPDX-License-Identifier: Apache-2.0
//! Claim and credential disclosure configuration.

use super::*;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureConfig {
    #[serde(default = "default_disclosure_profile")]
    pub default: String,
    #[serde(default = "default_disclosure_allowed")]
    pub allowed: Vec<String>,
    #[serde(default = "default_disclosure_downgrade")]
    pub downgrade: String,
}

impl Default for DisclosureConfig {
    fn default() -> Self {
        Self {
            default: default_disclosure_profile(),
            allowed: default_disclosure_allowed(),
            downgrade: default_disclosure_downgrade(),
        }
    }
}

pub(in crate::config) fn default_disclosure_profile() -> String {
    "redacted".to_string()
}

pub(in crate::config) fn default_disclosure_allowed() -> Vec<String> {
    vec!["redacted".to_string()]
}

pub(in crate::config) fn default_disclosure_downgrade() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialDisclosureConfig {
    #[serde(default)]
    pub allowed: Vec<String>,
}

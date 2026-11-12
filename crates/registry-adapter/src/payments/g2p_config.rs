// SPDX-License-Identifier: Apache-2.0
//! Caller and provider selection for authoritative BReg disbursements.

use super::{config::ConfigError, g2p_model::G2pConnectionSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pConnection {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64), extend("uniqueItems" = true)))]
    pub allowed_clients: Vec<String>,
    pub required_scope: String,
    pub binding: G2pConnectionSnapshot,
}

impl G2pConnection {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if registry_platform_yaml::LocalId::new(self.id.clone()).is_err()
            || self.allowed_clients.is_empty()
            || self.allowed_clients.len() > 64
            || self
                .allowed_clients
                .iter()
                .any(|id| !super::config::text(id, 128))
            || self.allowed_clients.iter().collect::<BTreeSet<_>>().len()
                != self.allowed_clients.len()
            || !super::config::text(&self.required_scope, 128)
        {
            return Err(ConfigError);
        }
        self.binding.validate().map_err(|_| ConfigError)
    }
}

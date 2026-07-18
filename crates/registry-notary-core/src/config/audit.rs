// SPDX-License-Identifier: Apache-2.0
//! Evidence audit sink configuration.

use super::*;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuditConfig {
    #[serde(default = "default_audit_sink")]
    pub sink: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub hash_secret_env: Option<String>,
    #[serde(default)]
    pub max_size_mb: Option<u64>,
    #[serde(default)]
    pub max_files: Option<u32>,
    #[serde(default)]
    pub syslog_socket_path: Option<String>,
}

impl Default for EvidenceAuditConfig {
    fn default() -> Self {
        Self {
            sink: default_audit_sink(),
            path: None,
            hash_secret_env: None,
            max_size_mb: None,
            max_files: None,
            syslog_socket_path: None,
        }
    }
}

impl EvidenceAuditConfig {
    pub const DEFAULT_MAX_SIZE_MB: u64 = 100;
    pub const DEFAULT_MAX_FILES: u32 = 14;

    pub fn max_size_bytes(&self) -> u64 {
        self.max_size_mb.unwrap_or(Self::DEFAULT_MAX_SIZE_MB) * 1024 * 1024
    }

    pub fn max_files(&self) -> u32 {
        self.max_files.unwrap_or(Self::DEFAULT_MAX_FILES)
    }
}

pub(super) fn default_audit_sink() -> String {
    "stdout".to_string()
}

/// A durable audit sink retains the evidence trail beyond process stdout.
///
/// `stdout` and `none` are not durable, retained sinks for a production-shaped
/// deployment; `file`, `jsonl`, and `syslog` write to a retained destination.
pub(super) fn audit_sink_is_durable(config: &EvidenceAuditConfig) -> bool {
    matches!(config.sink.as_str(), "file" | "jsonl" | "syslog")
}

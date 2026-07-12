// SPDX-License-Identifier: Apache-2.0
//! Datasource capability profiles.
//!
//! Capabilities are derived from the configured source and materialization
//! mode. Operators should not tune these directly; they exist so validation,
//! docs, and future connector planning share one conservative contract.

use super::{MaterializationMode, SourceConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushdownCapability {
    Supported,
    GatewayOnly,
    Unsupported,
}

impl PushdownCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::GatewayOnly => "gateway_only",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceCapabilities {
    pub materialization_supported: bool,
    pub filter_pushdown: PushdownCapability,
    pub projection_pushdown: PushdownCapability,
    pub limit_pushdown: PushdownCapability,
    pub strong_validators: bool,
    pub snapshot_provenance: bool,
    pub mtime_refresh: bool,
}

impl SourceCapabilities {
    const SNAPSHOT: Self = Self {
        materialization_supported: true,
        filter_pushdown: PushdownCapability::GatewayOnly,
        projection_pushdown: PushdownCapability::GatewayOnly,
        limit_pushdown: PushdownCapability::GatewayOnly,
        strong_validators: true,
        snapshot_provenance: true,
        mtime_refresh: true,
    };
}

pub fn source_capabilities(
    _source: &SourceConfig,
    _materialization: MaterializationMode,
) -> SourceCapabilities {
    SourceCapabilities::SNAPSHOT
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::PostgresTableConfig;

    fn postgres_table_source() -> SourceConfig {
        SourceConfig::Postgres {
            connection_env: "DATABASE_URL".to_string(),
            table: Some(PostgresTableConfig {
                schema: "public".to_string(),
                name: "records".to_string(),
            }),
            query: None,
            change_token_sql: None,
            connect_timeout: Duration::from_secs(5),
            query_timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn snapshot_profile_keeps_snapshot_semantics() {
        let capabilities =
            source_capabilities(&postgres_table_source(), MaterializationMode::Snapshot);

        assert_eq!(
            capabilities.filter_pushdown,
            PushdownCapability::GatewayOnly
        );
        assert!(capabilities.materialization_supported);
        assert!(capabilities.strong_validators);
        assert!(capabilities.snapshot_provenance);
        assert!(capabilities.mtime_refresh);
    }
}

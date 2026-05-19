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
    pub live_query_source: bool,
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
        live_query_source: false,
        mtime_refresh: true,
    };

    const POSTGRES_LIVE_TABLE: Self = Self {
        materialization_supported: true,
        filter_pushdown: PushdownCapability::GatewayOnly,
        projection_pushdown: PushdownCapability::Supported,
        limit_pushdown: PushdownCapability::GatewayOnly,
        strong_validators: false,
        snapshot_provenance: false,
        live_query_source: false,
        mtime_refresh: false,
    };

    const UNSUPPORTED_LIVE: Self = Self {
        materialization_supported: false,
        filter_pushdown: PushdownCapability::Unsupported,
        projection_pushdown: PushdownCapability::Unsupported,
        limit_pushdown: PushdownCapability::Unsupported,
        strong_validators: false,
        snapshot_provenance: false,
        live_query_source: false,
        mtime_refresh: false,
    };
}

pub fn source_capabilities(
    source: &SourceConfig,
    materialization: MaterializationMode,
) -> SourceCapabilities {
    match (source, materialization) {
        (_, MaterializationMode::Snapshot) => SourceCapabilities::SNAPSHOT,
        (
            SourceConfig::Postgres {
                table: Some(_),
                query: None,
                ..
            },
            MaterializationMode::Live,
        ) => SourceCapabilities::POSTGRES_LIVE_TABLE,
        _ => SourceCapabilities::UNSUPPORTED_LIVE,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
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
            live_max_connections: 8,
        }
    }

    fn postgres_query_source() -> SourceConfig {
        SourceConfig::Postgres {
            connection_env: "DATABASE_URL".to_string(),
            table: None,
            query: Some("select id from records".to_string()),
            change_token_sql: None,
            connect_timeout: Duration::from_secs(5),
            query_timeout: Duration::from_secs(30),
            live_max_connections: 8,
        }
    }

    #[test]
    fn postgres_live_table_profile_is_narrow_and_safe() {
        let capabilities = source_capabilities(&postgres_table_source(), MaterializationMode::Live);

        assert_eq!(
            capabilities.filter_pushdown,
            PushdownCapability::GatewayOnly
        );
        assert_eq!(
            capabilities.projection_pushdown,
            PushdownCapability::Supported
        );
        assert_eq!(capabilities.limit_pushdown, PushdownCapability::GatewayOnly);
        assert!(capabilities.materialization_supported);
        assert!(!capabilities.strong_validators);
        assert!(!capabilities.snapshot_provenance);
        assert!(!capabilities.live_query_source);
        assert!(!capabilities.mtime_refresh);
    }

    #[test]
    fn file_live_profile_is_unsupported() {
        let source = SourceConfig::File {
            path: PathBuf::from("records.csv"),
            format: None,
        };
        let capabilities = source_capabilities(&source, MaterializationMode::Live);

        assert_eq!(
            capabilities.filter_pushdown,
            PushdownCapability::Unsupported
        );
        assert_eq!(
            capabilities.projection_pushdown,
            PushdownCapability::Unsupported
        );
        assert!(!capabilities.materialization_supported);
    }

    #[test]
    fn postgres_live_query_profile_is_unsupported() {
        let capabilities = source_capabilities(&postgres_query_source(), MaterializationMode::Live);

        assert_eq!(
            capabilities.filter_pushdown,
            PushdownCapability::Unsupported
        );
        assert_eq!(
            capabilities.projection_pushdown,
            PushdownCapability::Unsupported
        );
        assert_eq!(capabilities.limit_pushdown, PushdownCapability::Unsupported);
        assert!(!capabilities.materialization_supported);
        assert!(!capabilities.live_query_source);
        assert!(!capabilities.mtime_refresh);
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

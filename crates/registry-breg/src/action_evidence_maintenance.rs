// SPDX-License-Identifier: Apache-2.0
//! Operator-only erasure of expired protected action Evidence material.

use std::path::Path;

use crate::mutation::{erase_expired_action_evidence, MutationError};
use crate::postgres::verify_migration_role;
use crate::runtime_config::load_runtime_config;

/// Erase only material whose declared expiry has passed. The configured
/// migration identity supplies deletion authority; runtime credentials do not.
/// Diagnostics return no connection, selector, assertion or provider values.
pub async fn erase_expired(path: &Path, before: &str) -> Result<u64, MutationError> {
    if !path.is_absolute() {
        return Err(MutationError::InvalidRequest);
    }
    let before = chrono::DateTime::parse_from_rfc3339(before)
        .map_err(|_| MutationError::InvalidRequest)?
        .with_timezone(&chrono::Utc);
    if before > chrono::Utc::now() {
        return Err(MutationError::InvalidRequest);
    }
    let config = load_runtime_config(path).map_err(|_| MutationError::Unavailable)?;
    let runtime_pool = config
        .runtime_database_connection_config()
        .map_err(|_| MutationError::Unavailable)?
        .build_pool()
        .map_err(|_| MutationError::Unavailable)?;
    let mut runtime_client = runtime_pool
        .get()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    crate::startup::prepare_startup(
        config.package().root(),
        &config.package_load_context(),
        &mut runtime_client,
        config.database().roles().migration(),
        config.database().roles().runtime(),
    )
    .await
    .map_err(|_| MutationError::Unavailable)?;
    drop(runtime_client);
    let pool = config
        .migration_database_connection_config()
        .map_err(|_| MutationError::Unavailable)?
        .build_pool()
        .map_err(|_| MutationError::Unavailable)?;
    let client = pool.get().await.map_err(|_| MutationError::Unavailable)?;
    let client: &tokio_postgres::Client = &client;
    verify_migration_role(client, config.database().roles().migration())
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let timeouts = config.operational_timeouts();
    client.query_one(
        "SELECT set_config('lock_timeout', $1, false), set_config('statement_timeout', $2, false)",
        &[&format!("{}ms", timeouts.migration_lock.as_millis()), &format!("{}ms", timeouts.migration_statement.as_millis())],
    ).await.map_err(|_| MutationError::Unavailable)?;
    erase_expired_action_evidence(client, before).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_or_future_boundaries_fail_before_configuration_io() {
        for (path, boundary) in [
            ("relative.yaml", "2020-01-01T00:00:00Z"),
            ("/nonexistent/config.yaml", "private-invalid-boundary"),
            ("/nonexistent/config.yaml", "9999-01-01T00:00:00Z"),
        ] {
            assert!(matches!(
                erase_expired(Path::new(path), boundary).await,
                Err(MutationError::InvalidRequest)
            ));
        }
    }
}

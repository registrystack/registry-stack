// SPDX-License-Identifier: Apache-2.0

//! The runtime identity preflight every delivery transaction runs, read from
//! the shared activation record.
//!
//! A worker serves only the package it was started with. Before it claims,
//! finalizes, or replays a delivery it checks, inside the same transaction,
//! that the activation record still names that package for that database.
//! A runtime left running across an activation then stops delivering rather
//! than serving work under a package that is no longer active.

use registry_platform_activation::{check_active_package, Layout};
use tokio_postgres::Transaction;

use super::seams::DeliveryError;

/// Check that the activation record in `layout` names `database_id` and
/// `package_digest` as the active package.
///
/// The transaction's `lock_timeout` is set to `lock_timeout_ms` first, so a
/// concurrent activation holding the ledger makes this attempt fail rather
/// than wait. The read takes no advisory lock: an activation takes its own
/// exclusive lock and may verify retained deliveries on another connection,
/// and a shared advisory lock held here would wait on it while it waits on
/// this worker.
///
/// # Errors
///
/// [`DeliveryError::Unavailable`] when the read fails, nothing is activated,
/// or the active package or database differs. The reason is never carried.
pub async fn verify_active_package(
    transaction: &Transaction<'_>,
    layout: &Layout,
    database_id: &str,
    package_digest: &str,
    lock_timeout_ms: u32,
) -> Result<(), DeliveryError> {
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1::text, true)",
            &[&format!("{lock_timeout_ms}ms")],
        )
        .await
        .map_err(|_| DeliveryError::Unavailable)?;
    check_active_package(transaction, layout, database_id, package_digest)
        .await
        .map(drop)
        .map_err(|_| DeliveryError::Unavailable)
}

// SPDX-License-Identifier: Apache-2.0
//! A retention cutoff after every completion the database has recorded.

use chrono::{DateTime, Utc};

/// Retention compares this cutoff with completion and transaction times from
/// the same database clock.
pub async fn retention_cutoff(client: &tokio_postgres::Client) -> DateTime<Utc> {
    client
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .expect("database clock")
        .get(0)
}

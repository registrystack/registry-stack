// SPDX-License-Identifier: Apache-2.0
//! A retention cutoff that every completion the database has recorded falls
//! before, whatever the offset between the host and database clocks.

use chrono::{DateTime, Utc};
use std::time::{Duration, Instant};

/// The database's current time, returned once the host clock has passed it
/// too. Retention compares the cutoff with completion times the database
/// recorded, and refuses a cutoff in the host's future.
pub async fn retention_cutoff(client: &tokio_postgres::Client) -> DateTime<Utc> {
    let cutoff: DateTime<Utc> = client
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .expect("database clock")
        .get(0);
    let limit = Instant::now() + Duration::from_secs(5);
    while Utc::now() <= cutoff {
        assert!(
            Instant::now() < limit,
            "the host clock trails the database clock by more than five seconds"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cutoff
}

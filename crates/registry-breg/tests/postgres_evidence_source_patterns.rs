// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

#[path = "support/evidence_source_patterns.rs"]
#[allow(dead_code)]
mod evidence_source_patterns;

use evidence_source_patterns::CASES;
use postgres_harness::TestDatabase;

/// A declared field pattern becomes `CHECK (column ~ pattern)` on a string or
/// text column with the generated `pg_catalog.pg_c_utf8` collation, so each
/// recorded value is read here under that collation with the same operator.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_reads_each_tabled_pattern_as_recorded() {
    let database = TestDatabase::create(1).await;
    let mut mismatches = Vec::new();
    for case in CASES {
        for (value, recorded) in case.postgres {
            let row = database
                .admin
                .query_one(
                    "SELECT ($1::text COLLATE pg_catalog.pg_c_utf8) ~ $2::text",
                    &[value, &case.pattern],
                )
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", case.pattern));
            let matched: bool = row.get(0);
            if matched != *recorded {
                mismatches.push(format!(
                    "{} on {value:?}: PostgreSQL answers {matched}",
                    case.pattern
                ));
            }
        }
    }
    database.cleanup().await;
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

//! Shared read-only extract execution used by Evidence pack routes.

pub use registry_adapter_engine::component::sqlite_extract::{
    SqliteExtractError, SqliteExtractPlan, SqliteExtractSource,
};
pub use registry_platform_sqlite::{
    cause, check_statement_offline, CapturedSnapshot, ColumnContract, ColumnType,
    ParameterContract, StatementContract, StatementLimits, Value,
};

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use chrono::{DateTime, Utc};
    use registry_platform_sqlite::materialize_fixture;
    use serde_json::json;

    use super::*;

    fn instant(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn contract(sql: &str) -> StatementContract {
        StatementContract {
            sql: sql.to_owned(),
            columns: vec![
                ColumnContract {
                    name: "id".to_owned(),
                    value_type: ColumnType::String,
                },
                ColumnContract {
                    name: "active".to_owned(),
                    value_type: ColumnType::Boolean,
                },
                ColumnContract {
                    name: "observed_at".to_owned(),
                    value_type: ColumnType::String,
                },
            ],
            parameters: vec![
                ParameterContract {
                    name: "id".to_owned(),
                    required: true,
                },
                ParameterContract {
                    name: "evidence_now".to_owned(),
                    required: false,
                },
            ],
            limits: StatementLimits {
                maximum_rows: 2,
                maximum_cell_bytes: 1024,
                maximum_response_bytes: 8192,
                maximum_statement_steps: 100_000,
                timeout: Duration::from_secs(2),
                concurrency: 2,
            },
            schema: None,
        }
    }

    fn extract() -> (tempfile::TempDir, CapturedSnapshot) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extract.sqlite");
        materialize_fixture(
            &path,
            "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT);
             INSERT INTO evidence_extract VALUES('2026-10-31T12:00:00Z', 'synthetic-publisher', 'extract-a');
             CREATE TABLE people(id TEXT, active INTEGER);
             INSERT INTO people VALUES('0007', 1);",
        )
        .unwrap();
        let captured = CapturedSnapshot::capture(&path).unwrap();
        (directory, captured)
    }

    #[tokio::test]
    async fn current_shared_extract_executes_typed_parameters_and_host_clock() {
        let (_directory, captured) = extract();
        let source = SqliteExtractSource::open(
            captured,
            contract("SELECT id, active, :evidence_now AS observed_at FROM people WHERE id = :id"),
            Duration::from_secs(3600),
        )
        .unwrap();
        let parameters = BTreeMap::from([("id".to_owned(), Value::String("0007".to_owned()))]);
        let result = source
            .execute(&parameters, instant("2026-10-31T12:30:00Z"))
            .await
            .unwrap();
        assert_eq!(
            result,
            json!({"rows":[{"id":"0007","active":true,"observed_at":"2026-10-31T12:30:00Z"}],"extract":{"publishedAt":"2026-10-31T12:00:00Z","publisher":"synthetic-publisher","extractId":"extract-a"}})
        );
    }

    #[tokio::test]
    async fn freshness_is_inclusive_and_refuses_one_instant_beyond_the_reviewed_age() {
        let (_directory, captured) = extract();
        let source = SqliteExtractSource::open(
            captured,
            contract("SELECT id, active, :evidence_now AS observed_at FROM people WHERE id = :id"),
            Duration::from_secs(3600),
        )
        .unwrap();
        let parameters = BTreeMap::from([("id".to_owned(), Value::String("0007".to_owned()))]);
        assert!(source
            .execute(&parameters, instant("2026-10-31T13:00:00Z"))
            .await
            .is_ok());
        assert!(matches!(
            source
                .execute(&parameters, instant("2026-10-31T13:00:01Z"))
                .await,
            Err(SqliteExtractError::Stale)
        ));
    }

    #[test]
    fn current_shared_extract_refuses_mutating_sql_before_execution() {
        let (_directory, captured) = extract();
        let result = SqliteExtractSource::open(
            captured,
            contract(
                "UPDATE people SET active = 0 WHERE id = :id RETURNING id, active, :evidence_now AS observed_at",
            ),
            Duration::from_secs(3600),
        );
        assert!(matches!(result, Err(SqliteExtractError::Statement(_))));
    }

    #[tokio::test]
    async fn current_shared_extract_accounts_metadata_and_rows_against_response_bound() {
        let (_directory, captured) = extract();
        let mut reviewed =
            contract("SELECT id, active, :evidence_now AS observed_at FROM people WHERE id = :id");
        reviewed.limits.maximum_response_bytes = 150;
        let source =
            SqliteExtractSource::open(captured, reviewed, Duration::from_secs(3600)).unwrap();
        let parameters = BTreeMap::from([("id".to_owned(), Value::String("0007".to_owned()))]);
        assert!(matches!(
            source
                .execute(&parameters, instant("2026-10-31T12:30:00Z"))
                .await,
            Err(SqliteExtractError::Statement(
                registry_platform_sqlite::ErrorKind::ResponseTooLarge
            ))
        ));
    }
}

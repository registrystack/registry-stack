// SPDX-License-Identifier: Apache-2.0

//! Disclosure conditions against a real PostgreSQL database.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

// The real-HTTP fixture is shared by the history and proposal suites.
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;

#[path = "disclosure/fields.rs"]
mod fields;
#[path = "disclosure/fixture.rs"]
#[allow(dead_code)]
mod fixture;
#[path = "disclosure/history.rs"]
mod history;
#[path = "disclosure/proposals.rs"]
mod proposals;
#[path = "disclosure/records.rs"]
mod records;

mod equivalence {
    use super::fixture::{quote_identifier, Fixture};
    use registry_breg::contract::DisclosureWhenPredicate;
    use registry_breg::disclosure::{when_matches, when_sql};
    use serde_json::{json, Map, Value};

    /// Rows over every null, absent, equal and unequal combination of
    /// `protection-level` and `history-protected` on `person`.
    const LEVELS: [Option<&str>; 4] = [
        None,
        Some("protected"),
        Some("none"),
        Some("substitute-address"),
    ];
    const FLAGS: [Option<bool>; 3] = [None, Some(true), Some(false)];

    fn predicate_sets() -> Vec<Vec<DisclosureWhenPredicate>> {
        let parse = |value: Value| -> Vec<DisclosureWhenPredicate> {
            serde_json::from_value(value).expect("predicates parse")
        };
        vec![
            parse(json!([{"type":"field-equals","field":"protection-level","value":"protected"}])),
            parse(
                json!([{"type":"field-in","field":"protection-level","values":["protected","substitute-address"]}]),
            ),
            parse(json!([{"type":"field-is-null","field":"protection-level"}])),
            parse(json!([{"type":"field-is-not-null","field":"protection-level"}])),
            parse(json!([{"type":"field-equals","field":"history-protected","value":true}])),
            parse(json!([{"type":"field-equals","field":"history-protected","value":false}])),
            parse(json!([{"type":"field-is-null","field":"history-protected"},
                         {"type":"field-in","field":"protection-level","values":["none"]}])),
            parse(
                json!([{"type":"field-is-not-null","field":"history-protected"},
                         {"type":"field-equals","field":"protection-level","value":"protected"}]),
            ),
        ]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn when_sql_and_when_matches_agree_on_null_absent_equal_unequal_and_in() {
        let fixture = Fixture::build(1).await;
        let entity = &fixture.registry.entities()["person"];
        let mut states = Vec::new();
        for (level_index, level) in LEVELS.iter().enumerate() {
            for (flag_index, flag) in FLAGS.iter().enumerate() {
                let record_id =
                    format!("00000000-0000-0000-0000-00000000e{level_index}{flag_index}0");
                let mut values = vec![("family-name", json!("Equivalence"))];
                let mut state = Map::new();
                if let Some(level) = level {
                    values.push(("protection-level", json!(level)));
                    state.insert("protection-level".to_owned(), json!(level));
                }
                if let Some(flag) = flag {
                    values.push(("history-protected", json!(flag)));
                    state.insert("history-protected".to_owned(), json!(flag));
                }
                fixture.insert("person", &record_id, &values).await;
                states.push((record_id, state));
            }
        }
        let table = quote_identifier(&entity.physical_table);
        for when in predicate_sets() {
            let sql = when_sql(entity, &when, &|field| {
                quote_identifier(&entity.fields[field].physical_name)
            });
            let rows = fixture
                .database
                .admin
                .query(
                    &format!("SELECT record_id::text, {sql} FROM registry_data.{table}"),
                    &[],
                )
                .await
                .unwrap_or_else(|error| panic!("{sql} executes: {error}"));
            for (record_id, state) in &states {
                let row = rows
                    .iter()
                    .find(|row| row.get::<_, String>(0) == *record_id)
                    .expect("the row is selected");
                // A two-valued result: PostgreSQL never answers null.
                let sql_result: Option<bool> = row.get(1);
                assert_eq!(
                    sql_result,
                    Some(when_matches(entity, &when, state).unwrap()),
                    "{sql} on {state:?}"
                );
            }
        }
        fixture.database.cleanup().await;
    }
}

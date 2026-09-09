// SPDX-License-Identifier: Apache-2.0

//! One problem-code catalogue, read from the three places that publish it.
//!
//! The engine registers every code in `ProblemCode`, the published API
//! reference names the ones a reader is given, and the Rust client accepts the
//! ones a caller can be handed. Nothing else holds the three in step, so each
//! assertion below names the catalogue that is behind.

use std::collections::{BTreeMap, BTreeSet};

use registry_breg::problem::ProblemCode;
use registry_breg_client::BRegProblemCode;
use serde::Deserialize;

/// The published data the docs site renders the API reference tables from.
const API_REFERENCE: &str = include_str!("../../../docs/site/src/data/breg-api.yaml");

/// One rendered table. Unknown members are refused, so a change to the shape of
/// the reference fails here rather than matching nothing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    id: String,
    title: String,
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
}

/// One published problem code and the status it is documented under.
struct PublishedCode {
    code: String,
    status: u16,
}

/// Read the problem-code table, proving its shape before reading any cell.
fn published_codes() -> Vec<PublishedCode> {
    let tables: Vec<Table> = serde_norway::from_str(API_REFERENCE)
        .expect("the API reference parses as the tables the docs site renders");
    let table = tables
        .into_iter()
        .find(|table| table.id == "problem-codes")
        .expect("the API reference carries a problem-codes table");
    assert_eq!(
        table.title, "Problem codes",
        "the problem-codes table was retitled, so this test may be reading another table"
    );
    assert_eq!(
        table.columns,
        ["Code", "Status", "When"],
        "the problem-codes columns moved, so the cells read below name something else"
    );
    assert!(
        !table.rows.is_empty(),
        "the problem-codes table is empty, so it documents nothing"
    );
    table
        .rows
        .iter()
        .map(|row| {
            assert_eq!(
                row.len(),
                3,
                "a problem-codes row does not carry the three documented columns: {row:?}"
            );
            let code = row[0]
                .strip_prefix('`')
                .and_then(|code| code.strip_suffix('`'))
                .unwrap_or_else(|| {
                    panic!("published code {} is not one code in backticks", row[0])
                });
            let status = row[1].parse().unwrap_or_else(|_| {
                panic!("published status {} for {code} is not a status", row[1])
            });
            PublishedCode {
                code: code.to_owned(),
                status,
            }
        })
        .collect()
}

/// Every registered code and the one status the engine answers it under.
fn registered_statuses() -> BTreeMap<&'static str, u16> {
    ProblemCode::ALL
        .iter()
        .map(|code| (code.code(), code.status()))
        .collect()
}

#[test]
fn every_documented_code_has_a_published_row() {
    let published: BTreeSet<String> = published_codes().into_iter().map(|row| row.code).collect();
    for code in ProblemCode::DOCUMENTED {
        assert!(
            published.contains(code.code()),
            "docs/site/src/data/breg-api.yaml is behind the engine: no problem-codes row documents {}",
            code.code()
        );
    }
}

#[test]
fn every_published_row_names_a_registered_code_under_its_status() {
    let registered = registered_statuses();
    for row in published_codes() {
        let status = registered.get(row.code.as_str()).unwrap_or_else(|| {
            panic!(
                "docs/site/src/data/breg-api.yaml is ahead of the engine: {} is not a registered problem code",
                row.code
            )
        });
        assert_eq!(
            row.status, *status,
            "docs/site/src/data/breg-api.yaml is behind the engine: {} is documented under {} and answered under {status}",
            row.code, row.status
        );
    }
}

#[test]
fn the_client_registers_the_codes_the_engine_registers() {
    let engine: BTreeSet<&str> = registered_statuses().into_keys().collect();
    let client: BTreeSet<&str> = BRegProblemCode::ALL
        .iter()
        .map(|code| code.code())
        .collect();
    for code in &engine {
        assert!(
            client.contains(code),
            "crates/registry-breg-client is behind the engine: it accepts no {code} problem"
        );
    }
    for code in &client {
        assert!(
            engine.contains(code),
            "crates/registry-breg-client is ahead of the engine: {code} is not a registered problem code"
        );
    }
}

#[test]
fn the_client_answers_each_code_under_the_engine_status() {
    let registered = registered_statuses();
    for code in &BRegProblemCode::ALL {
        let status = registered.get(code.code()).unwrap_or_else(|| {
            panic!(
                "crates/registry-breg-client is ahead of the engine: {} is not a registered problem code",
                code.code()
            )
        });
        assert_eq!(
            code.status(),
            *status,
            "crates/registry-breg-client is behind the engine: {} is accepted under {} and answered under {status}",
            code.code(),
            code.status()
        );
    }
}

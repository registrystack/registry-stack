// SPDX-License-Identifier: Apache-2.0

//! One Casework problem-code catalogue, read from the places that publish it.
//!
//! The service registers every code in `ProblemCode`, the published API
//! reference names the ones a reader is given, the Rust client accepts the ones
//! a caller can be handed, and the Node and Python typings name the ones a
//! caller can write. Nothing else holds them in step, so each assertion below
//! names the catalogue that is behind.

use std::collections::{BTreeMap, BTreeSet};

use registry_casework::problem::ProblemCode;
use registry_casework_client::CaseworkProblemCode;
use serde::Deserialize;

/// The published data the docs site renders the Casework reference tables from.
const API_REFERENCE: &str = include_str!("../../../docs/site/src/data/casework-api.yaml");

/// The typings the standalone Node binding publishes.
const NODE_TYPINGS: &str =
    include_str!("../../../crates/registry-casework-client-node/client.d.ts");

/// The typings the unified Node facade publishes for the same binding.
const FACADE_TYPINGS: &str =
    include_str!("../../../crates/registry-stack-client-node/casework/client.d.ts");

/// The stub the Python binding publishes.
const PYTHON_STUB: &str = include_str!(
    "../../../crates/registry-casework-client-py/python/registry_casework_client/__init__.pyi"
);

/// The source that declares the closed validation reasons the service answers.
const CORE_HOSTED: &str = include_str!("../../../crates/registry-casework-core/src/hosted.rs");

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
            assert!(
                !row[2].trim().is_empty(),
                "the published row for {code} documents no condition"
            );
            PublishedCode {
                code: code.to_owned(),
                status,
            }
        })
        .collect()
}

/// Every registered code and the one status the service answers it under.
fn registered_statuses() -> BTreeMap<&'static str, u16> {
    ProblemCode::ALL
        .iter()
        .map(|code| (code.code(), code.status().as_u16()))
        .collect()
}

/// The members of one TypeScript string-literal union, in declaration order.
fn typescript_union(source: &str, name: &str) -> Vec<String> {
    let declaration = format!("export type {name} =");
    let start = source
        .find(&declaration)
        .unwrap_or_else(|| panic!("the typings declare no {name} union"))
        + declaration.len();
    let body = &source[start..];
    let end = body
        .find("\nexport ")
        .unwrap_or_else(|| panic!("the {name} union is never closed by another declaration"));
    quoted_members(&body[..end], '\'')
}

/// The members of the Python `Literal` alias of this name, in declaration order.
fn python_literal(source: &str, name: &str) -> Vec<String> {
    let declaration = format!("{name}: TypeAlias = Literal[");
    let start = source
        .find(&declaration)
        .unwrap_or_else(|| panic!("the stub declares no {name} literal union"))
        + declaration.len();
    let body = &source[start..];
    let end = body
        .find(']')
        .unwrap_or_else(|| panic!("the {name} literal union is never closed"));
    quoted_members(&body[..end], '"')
}

/// Every quoted member of a union body, refusing an unterminated quote.
fn quoted_members(body: &str, quote: char) -> Vec<String> {
    let mut members = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find(quote) {
        let after = &rest[open + quote.len_utf8()..];
        let close = after
            .find(quote)
            .unwrap_or_else(|| panic!("a union member is never closed: {after}"));
        members.push(after[..close].to_owned());
        rest = &after[close + quote.len_utf8()..];
    }
    members
}

/// The serialized names of one closed enum in the core model, read from the
/// declaration rather than a copy of it.
fn core_enum_members(name: &str) -> Vec<String> {
    let declaration = format!("pub enum {name} {{");
    let start = CORE_HOSTED
        .find(&declaration)
        .unwrap_or_else(|| panic!("registry-casework-core declares no {name}"))
        + declaration.len();
    let body = &CORE_HOSTED[start..];
    let end = body
        .find('}')
        .unwrap_or_else(|| panic!("the {name} declaration is never closed"));
    body[..end]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with('#'))
        .map(|line| snake_case(line.trim_end_matches(',')))
        .collect()
}

/// One variant name under the `snake_case` rename the core model serializes by.
fn snake_case(variant: &str) -> String {
    let mut name = String::new();
    for (index, character) in variant.char_indices() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                name.push('_');
            }
            name.push(character.to_ascii_lowercase());
        } else {
            name.push(character);
        }
    }
    name
}

/// One published union, compared with the service catalogue in both directions.
fn assert_same_catalogue(published: &[String], publisher: &str) {
    assert!(
        !published.is_empty(),
        "{publisher} publishes an empty problem-code catalogue"
    );
    let mut sorted = published.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        published.len(),
        "{publisher} names a problem code twice"
    );
    let registered: BTreeSet<&str> = registered_statuses().into_keys().collect();
    let published: BTreeSet<&str> = published.iter().map(String::as_str).collect();
    for code in &registered {
        assert!(
            published.contains(code),
            "{publisher} is behind the service: it names no {code} problem"
        );
    }
    for code in &published {
        assert!(
            registered.contains(code),
            "{publisher} is ahead of the service: {code} is not a registered problem code"
        );
    }
}

#[test]
fn every_registered_code_has_a_published_row() {
    let published: BTreeSet<String> = published_codes().into_iter().map(|row| row.code).collect();
    for code in ProblemCode::ALL {
        assert!(
            published.contains(code.code()),
            "docs/site/src/data/casework-api.yaml is behind the service: no problem-codes row documents {}",
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
                "docs/site/src/data/casework-api.yaml is ahead of the service: {} is not a registered problem code",
                row.code
            )
        });
        assert_eq!(
            row.status, *status,
            "docs/site/src/data/casework-api.yaml is behind the service: {} is documented under {} and answered under {status}",
            row.code, row.status
        );
    }
}

#[test]
fn the_client_registers_the_codes_the_service_registers() {
    let service: BTreeSet<&str> = registered_statuses().into_keys().collect();
    let client: BTreeSet<&str> = CaseworkProblemCode::ALL
        .iter()
        .map(CaseworkProblemCode::code)
        .collect();
    for code in &service {
        assert!(
            client.contains(code),
            "crates/registry-casework-client is behind the service: it accepts no {code} problem"
        );
    }
    for code in &client {
        assert!(
            service.contains(code),
            "crates/registry-casework-client is ahead of the service: {code} is not a registered problem code"
        );
    }
}

#[test]
fn the_client_answers_each_code_under_the_service_status() {
    let registered = registered_statuses();
    for code in CaseworkProblemCode::ALL {
        let status = registered.get(code.code()).unwrap_or_else(|| {
            panic!(
                "crates/registry-casework-client is ahead of the service: {} is not a registered problem code",
                code.code()
            )
        });
        assert_eq!(
            code.expected_status(),
            Some(*status),
            "crates/registry-casework-client is behind the service: {} is accepted under {:?} and answered under {status}",
            code.code(),
            code.expected_status()
        );
    }
}

#[test]
fn the_node_typings_name_the_codes_the_service_registers() {
    assert_same_catalogue(
        &typescript_union(NODE_TYPINGS, "KnownCaseworkProblemCode"),
        "crates/registry-casework-client-node/client.d.ts",
    );
}

#[test]
fn the_node_facade_typings_name_the_codes_the_service_registers() {
    assert_same_catalogue(
        &typescript_union(FACADE_TYPINGS, "KnownCaseworkProblemCode"),
        "crates/registry-stack-client-node/casework/client.d.ts",
    );
}

#[test]
fn the_python_stub_names_the_codes_the_service_registers() {
    assert_same_catalogue(
        &python_literal(PYTHON_STUB, "KnownCaseworkProblemCode"),
        "crates/registry-casework-client-py stub",
    );
}

#[test]
fn the_python_stub_names_the_validation_reasons_the_service_answers() {
    let registered = core_enum_members("HostedValidationReason");
    let published = python_literal(PYTHON_STUB, "HostedValidationReason");
    assert!(
        !registered.is_empty(),
        "registry-casework-core declares no validation reason, so this test proves nothing"
    );
    for reason in &registered {
        assert!(
            published.contains(reason),
            "crates/registry-casework-client-py stub is behind the service: it names no {reason} validation reason"
        );
    }
    for reason in &published {
        assert!(
            registered.contains(reason),
            "crates/registry-casework-client-py stub is ahead of the service: {reason} is not a registered validation reason"
        );
    }
}

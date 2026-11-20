// SPDX-License-Identifier: Apache-2.0

//! Proposal review canaries.

use super::fixture::{compile_fixture, REGISTRAR};
use registry_breg::disclosure::plan;
use serde_json::Map;

#[test]
fn a_record_that_is_not_flagged_withholds_nothing_in_review() {
    let registry = compile_fixture();
    let person = &registry.entities()["person"];
    let empty = Map::new();
    let registrar = plan(person, REGISTRAR);
    assert!(!registrar.withholds_record(&empty).unwrap());
    assert!(registrar.withheld_fields(&empty).unwrap().is_empty());
}

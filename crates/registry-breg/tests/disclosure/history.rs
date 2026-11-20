// SPDX-License-Identifier: Apache-2.0

//! History canaries: snapshots and revisions.

use super::fixture::{compile_fixture, EMERGENCY_REGISTRAR, PROTECTION_OFFICER, REGISTRAR};
use registry_breg::disclosure::plan;
use serde_json::{json, Map, Value};

#[test]
fn only_the_protection_officer_reads_the_history_of_a_flagged_person() {
    let registry = compile_fixture();
    let person = &registry.entities()["person"];
    let state: Map<String, Value> = json!({"history-protected": true})
        .as_object()
        .unwrap()
        .clone();
    assert!(plan(person, REGISTRAR).withholds_history(&state).unwrap());
    assert!(plan(person, EMERGENCY_REGISTRAR)
        .withholds_history(&state)
        .unwrap());
    assert!(!plan(person, PROTECTION_OFFICER)
        .withholds_history(&state)
        .unwrap());
}

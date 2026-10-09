// SPDX-License-Identifier: Apache-2.0
//! The retired `anonymous` member on a sealed predecessor: `false` said
//! nothing and is dropped, `true` granted unauthenticated access and is
//! refused, wherever an access profile or an action permission carries it.

use serde_json::{json, Value};

use super::{retire_predecessor_anonymous, PackageError};

const OWNERS: [&str; 2] = ["entities", "statisticalDatasets"];

/// A model whose every kind of site carries `anonymous: first`, except the
/// site at `site`, which carries `anonymous: at_site`.
fn model(site: Option<&str>, at_site: Value) -> Value {
    let value_for = |name: &str| {
        if site == Some(name) {
            at_site.clone()
        } else {
            json!(false)
        }
    };
    json!({
        "entities": {"person": {"accessProfiles": {"reader": {"anonymous": value_for("entity")}}}},
        "statisticalDatasets": {
            "households": {"accessProfiles": {"reader": {"anonymous": value_for("dataset")}}}
        },
        "actionInventory": {"actions": [
            {"permissions": [{"anonymous": value_for("action")}]}
        ]},
    })
}

fn retire(value: &mut Value) -> Result<(), PackageError> {
    retire_predecessor_anonymous(value, &OWNERS, "/actionInventory/actions")
}

#[test]
fn false_is_dropped_from_every_site() {
    let mut value = model(None, json!(false));
    retire(&mut value).expect("false is accepted");
    assert_eq!(
        value,
        json!({
            "entities": {"person": {"accessProfiles": {"reader": {}}}},
            "statisticalDatasets": {"households": {"accessProfiles": {"reader": {}}}},
            "actionInventory": {"actions": [{"permissions": [{}]}]},
        })
    );
}

#[test]
fn true_is_refused_at_every_site() {
    for site in ["entity", "dataset", "action"] {
        let mut value = model(Some(site), json!(true));
        assert!(
            matches!(retire(&mut value), Err(PackageError::Derivation)),
            "{site}"
        );
    }
}

#[test]
fn a_non_boolean_is_refused_at_every_site() {
    for site in ["entity", "dataset", "action"] {
        let mut value = model(Some(site), json!("yes"));
        assert!(
            matches!(retire(&mut value), Err(PackageError::Derivation)),
            "{site}"
        );
    }
}

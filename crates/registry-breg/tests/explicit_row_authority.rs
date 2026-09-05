// SPDX-License-Identifier: Apache-2.0

use registry_breg::contract::{
    AccessGrantSource, AccessRequirementsSource, ActionTargetGrantSource, ApplyTargetGrantSource,
    RequestPresenceGrantSource, ReviewStageTargetGrantSource,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

fn requires_explicit_rows<T: DeserializeOwned>(mut value: Value) {
    assert!(serde_json::from_value::<T>(value.clone()).is_err());
    value["rowBoundaries"] = Value::Null;
    assert!(serde_json::from_value::<T>(value.clone()).is_err());
    value["rowBoundaries"] = json!([]);
    assert!(serde_json::from_value::<T>(value.clone()).is_ok());
    value["rowBoundaries"] = json!([
        {"field":"district", "claim":"districts", "operator":"in"}
    ]);
    assert!(serde_json::from_value::<T>(value).is_ok());
}

#[test]
fn every_row_bearing_grant_requires_an_explicit_declaration() {
    requires_explicit_rows::<AccessGrantSource>(json!({
        "entity":"record", "operations":["get"]
    }));
    requires_explicit_rows::<ActionTargetGrantSource>(json!({"entity":"record"}));
    requires_explicit_rows::<ApplyTargetGrantSource>(json!({"entity":"record"}));
    requires_explicit_rows::<ReviewStageTargetGrantSource>(json!({
        "entity":"record", "readableFields":["label"]
    }));
    requires_explicit_rows::<RequestPresenceGrantSource>(json!({"requestType":"correction"}));
}

#[test]
fn invocation_and_mandatory_requirements_do_not_invent_row_grants() {
    let action: AccessGrantSource = serde_json::from_value(json!({
        "action":"register", "operations":["invoke"],
        "targets":[{"entity":"record", "rowBoundaries":[]}]
    }))
    .expect("invocation declares rows only at its targets");
    assert!(action.row_boundaries.is_empty());
    assert_eq!(action.targets.len(), 1);
    let floor: AccessRequirementsSource = serde_json::from_value(json!({
        "requiredScopes":["registry:read"]
    }))
    .expect("requirements constrain grants and do not grant rows");
    assert!(floor.row_boundaries.is_empty());
}

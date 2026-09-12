// SPDX-License-Identifier: Apache-2.0

use registry_breg::contract::{
    AccessPermissionSource, AccessProfileSource, AccessRequirementsSource,
    ActionTargetPermissionSource, ApplyTargetPermissionSource, RequestPresencePermissionSource,
    ReviewStageTargetPermissionSource,
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
    requires_explicit_rows::<AccessPermissionSource>(json!({
        "entity":"record", "operations":["get"]
    }));
    requires_explicit_rows::<ActionTargetPermissionSource>(json!({"entity":"record"}));
    requires_explicit_rows::<ApplyTargetPermissionSource>(json!({"entity":"record"}));
    requires_explicit_rows::<ReviewStageTargetPermissionSource>(json!({
        "entity":"record", "readableFields":["label"]
    }));
    requires_explicit_rows::<RequestPresencePermissionSource>(json!({"requestType":"correction"}));
}

#[test]
fn invocation_and_mandatory_requirements_do_not_invent_row_grants() {
    let action: AccessPermissionSource = serde_json::from_value(json!({
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

#[test]
fn membership_preserves_explicit_row_declarations_and_round_trips() {
    let boundaries = json!([{
        "field":"organization", "membershipEntity":"membership",
        "membershipKeyField":"organization", "principalField":"principal",
        "activeField":"active"
    }]);
    let mut grant = json!({
        "entity":"record", "operations":["get"], "membershipBoundaries": boundaries
    });
    requires_explicit_rows::<AccessPermissionSource>(grant.clone());
    grant["rowBoundaries"] = json!([]);
    let parsed: AccessPermissionSource = serde_json::from_value(grant).unwrap();
    assert_eq!(parsed.membership_boundaries.len(), 1);
    assert_eq!(
        serde_json::to_value(parsed).unwrap()["membershipBoundaries"],
        boundaries
    );

    requires_explicit_rows::<AccessProfileSource>(json!({
        "id":"member", "principalClaim":"sub", "operations":["get"],
        "membershipBoundaries": boundaries
    }));
}

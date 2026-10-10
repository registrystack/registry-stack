// SPDX-License-Identifier: Apache-2.0

use registry_breg::contract::{
    AccessProfileSource, AccessRequirementsSource, ActionPermissionSource,
    ActionTargetPermissionSource, ApplyTargetPermissionSource, EntityPermissionSource,
    RequestPresencePermissionSource,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// An authored grant states its row reach: `unrestricted`, or at least one
/// boundary. Nothing written, `null`, and an empty list are all refused.
fn requires_explicit_rows<T: DeserializeOwned>(mut value: Value) {
    assert!(serde_json::from_value::<T>(value.clone()).is_err());
    value["rowBoundaries"] = Value::Null;
    assert!(serde_json::from_value::<T>(value.clone()).is_err());
    value["rowBoundaries"] = json!([]);
    assert!(serde_json::from_value::<T>(value.clone()).is_err());
    value["rowBoundaries"] = json!("unrestricted");
    assert!(serde_json::from_value::<T>(value.clone()).is_ok());
    value["rowBoundaries"] = json!([
        {"field":"district", "claim":"districts", "operator":"in"}
    ]);
    assert!(serde_json::from_value::<T>(value).is_ok());
}

/// The compiled form carries the row reach as a list, empty when the grant
/// reaches every row, and still refuses a grant that carries none.
fn carries_compiled_rows<T: DeserializeOwned>(mut value: Value) {
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
    requires_explicit_rows::<EntityPermissionSource>(json!({
        "entity":"record", "operations":["get"]
    }));
    requires_explicit_rows::<ActionTargetPermissionSource>(json!({"entity":"record"}));
    carries_compiled_rows::<ApplyTargetPermissionSource>(json!({"entity":"record"}));
    carries_compiled_rows::<RequestPresencePermissionSource>(json!({"requestType":"correction"}));
}

#[test]
fn invocation_and_mandatory_requirements_do_not_invent_row_grants() {
    let mut invocation = json!({
        "action":"register", "operations":["invoke"],
        "targets":[{"entity":"record", "rowBoundaries":"unrestricted"}]
    });
    let action: ActionPermissionSource = serde_json::from_value(invocation.clone())
        .expect("invocation declares rows only at its targets");
    assert_eq!(action.targets.len(), 1);
    invocation["rowBoundaries"] = json!("unrestricted");
    assert!(serde_json::from_value::<ActionPermissionSource>(invocation).is_err());
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
    requires_explicit_rows::<EntityPermissionSource>(grant.clone());
    grant["rowBoundaries"] = json!("unrestricted");
    let parsed: EntityPermissionSource = serde_json::from_value(grant).unwrap();
    assert_eq!(parsed.membership_boundaries.len(), 1);
    assert_eq!(
        serde_json::to_value(parsed).unwrap()["membershipBoundaries"],
        boundaries
    );

    carries_compiled_rows::<AccessProfileSource>(json!({
        "id":"member", "principalClaim":"sub", "operations":["get"],
        "membershipBoundaries": boundaries
    }));
}

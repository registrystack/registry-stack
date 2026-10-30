// SPDX-License-Identifier: Apache-2.0

use super::{CompiledRegistryChangeTarget, CompiledRegistryChangeTargetKind};
use serde_json::{from_value, json, to_value};

#[test]
fn change_target_names_the_record_type_on_the_wire() {
    let target = CompiledRegistryChangeTarget {
        kind: CompiledRegistryChangeTargetKind::RecordType,
        record_type_id: Some("household".to_owned()),
        member_id: None,
    };
    let wire = json!({"kind": "record-type", "recordTypeId": "household"});

    assert_eq!(to_value(&target).unwrap(), wire);
    assert_eq!(
        from_value::<CompiledRegistryChangeTarget>(wire).unwrap(),
        target
    );
}

#[test]
fn change_target_refuses_the_retired_members() {
    for retired in [
        json!({"kind": "field", "entityId": "household", "memberId": "name"}),
        json!({"kind": "entity", "recordTypeId": "household"}),
    ] {
        assert!(
            from_value::<CompiledRegistryChangeTarget>(retired.clone()).is_err(),
            "{retired} must be refused"
        );
    }
}

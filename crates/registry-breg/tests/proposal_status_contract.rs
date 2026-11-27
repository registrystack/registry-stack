// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "schema")]

#[test]
fn every_proposal_availability_reason_is_in_the_served_schema() {
    let served = registry_breg::artifacts::availability_schema();
    for reason in registry_breg::lifecycle::ProposalAvailabilityReason::ALL {
        let wire = serde_json::to_value(reason).unwrap();
        assert!(
            served["properties"]["reason"]["enum"]
                .as_array()
                .unwrap()
                .contains(&wire),
            "served availability schema omits {wire}"
        );
        serde_json::from_value::<registry_breg_client::BRegAvailabilityReason>(wire).unwrap();
    }
    for recovery in registry_breg::lifecycle::ProposalLinkRecovery::ALL {
        let wire = serde_json::to_value(recovery).unwrap();
        assert!(
            served["properties"]["recovery"]["enum"]
                .as_array()
                .unwrap()
                .contains(&wire),
            "served availability schema omits {wire}"
        );
        serde_json::from_value::<registry_breg_client::BRegRecoveryHint>(wire).unwrap();
    }
}

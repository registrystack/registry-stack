// SPDX-License-Identifier: Apache-2.0

mod approved_set_support;
pub use approved_set_support::{project_authoring, trust, SIGNING_INPUT_MARKER_FILE};

use std::cell::RefCell;

use approved_set_support::approved_set::{
    assemble_initial_approved_set, assemble_updated_approved_set,
    load_approved_baseline_set_structure, AffectedLaneReplacements, ApprovedLaneV1,
    LaneVerificationSourceV1, ReviewedBuildUpdateV1, APPROVED_BASELINE_SET_SCHEMA_ID,
    APPROVED_BASELINE_SET_SCHEMA_VERSION,
};
use approved_set_support::{
    initial_lane, path_set, replacement_lane, reviewed_binding, verifier_for_initial,
};

#[test]
fn initial_assembly_emits_one_deterministic_value_free_entry_for_each_fixed_lane() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let first = temporary.path().join("approved-set.json");
    let second = temporary.path().join("approved-set-copy.json");
    let inputs = path_set(temporary.path());

    let first_report = assemble_initial_approved_set(&inputs, &first, verifier_for_initial)
        .expect("set assembles");
    let second_report =
        assemble_initial_approved_set(&inputs, &second, verifier_for_initial).expect("set repeats");

    assert_eq!(
        first_report.approved_set_digest,
        second_report.approved_set_digest
    );
    assert_eq!(
        std::fs::read(&first).expect("first set reads"),
        std::fs::read(&second).expect("second set reads")
    );
    assert_eq!(
        first_report.affected_lanes,
        ApprovedLaneV1::ALL,
        "initial review requires all three fixed lanes"
    );
    assert_eq!(
        first_report.approved_set.schema_id,
        APPROVED_BASELINE_SET_SCHEMA_ID
    );
    assert_eq!(
        first_report.approved_set.schema_version,
        APPROVED_BASELINE_SET_SCHEMA_VERSION
    );
    assert_eq!(
        first_report
            .approved_set
            .lanes
            .relay_consultation
            .interfaces
            .consultation_relay_notary,
        first_report
            .approved_set
            .lanes
            .notary
            .interfaces
            .consultation_relay_notary
    );
    assert!(first_report
        .approved_set
        .lanes
        .relay_public
        .interfaces
        .consultation_relay_notary
        .is_none());

    let json = String::from_utf8(std::fs::read(&first).expect("set reads")).expect("set is UTF-8");
    for forbidden in [
        "example-project",
        "production",
        "example-project-stream",
        temporary.path().to_str().expect("temporary path is UTF-8"),
        "secret",
    ] {
        assert!(
            !json.contains(forbidden),
            "portable set retained forbidden value {forbidden:?}"
        );
    }
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("set parses");
    assert_eq!(
        parsed["lanes"]
            .as_object()
            .expect("lanes are an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["notary", "relay-consultation", "relay-public"]
    );
    assert!(parsed["lanes"]["relay-public"].get("lane").is_none());
    assert!(parsed["lanes"]["relay-public"]
        .get("acceptance_identity")
        .is_none());
    assert_eq!(
        load_approved_baseline_set_structure(&first).expect("set round trips"),
        first_report.approved_set
    );
}

#[test]
fn update_reverifies_every_preceding_lane_and_only_replaces_reviewed_affected_lanes() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let preceding_file = temporary.path().join("approved-set.json");
    let next_file = temporary.path().join("approved-set.next.json");
    let inputs = path_set(temporary.path());
    let preceding = assemble_initial_approved_set(&inputs, &preceding_file, verifier_for_initial)
        .expect("initial set assembles")
        .approved_set;

    let reviewed = ReviewedBuildUpdateV1 {
        relay_public: None,
        relay_consultation: Some(reviewed_binding(ApprovedLaneV1::RelayConsultation)),
        notary: Some(reviewed_binding(ApprovedLaneV1::Notary)),
    };
    let replacements = AffectedLaneReplacements {
        relay_public: None,
        relay_consultation: Some(temporary.path().join("consultation-next")),
        notary: Some(temporary.path().join("notary-next")),
    };
    let requests = RefCell::new(Vec::new());

    let report = assemble_updated_approved_set(
        &preceding_file,
        &reviewed,
        &replacements,
        &next_file,
        |request| {
            requests
                .borrow_mut()
                .push((request.lane, request.source.clone()));
            Ok(match request.source {
                LaneVerificationSourceV1::PrecedingApprovedEntry { entry, .. } => {
                    let lane = initial_lane(request.lane);
                    assert_eq!(lane.entry(), entry.as_ref());
                    lane
                }
                LaneVerificationSourceV1::LaneDirectory(_) => replacement_lane(request.lane),
            })
        },
    )
    .expect("governed update assembles");

    let requests = requests.into_inner();
    assert_eq!(requests.len(), 5, "three preceding and two replacements");
    assert_eq!(
        requests
            .iter()
            .filter(|(_, source)| matches!(
                source,
                LaneVerificationSourceV1::PrecedingApprovedEntry { .. }
            ))
            .count(),
        3
    );
    assert_eq!(
        report.affected_lanes,
        vec![ApprovedLaneV1::RelayConsultation, ApprovedLaneV1::Notary]
    );
    assert_eq!(
        report.approved_set.lanes.relay_public,
        preceding.lanes.relay_public
    );
    assert_ne!(
        report.approved_set.lanes.relay_consultation,
        preceding.lanes.relay_consultation
    );
    assert_ne!(report.approved_set.lanes.notary, preceding.lanes.notary);
    assert_eq!(
        report
            .approved_set
            .lanes
            .relay_consultation
            .interfaces
            .consultation_relay_notary,
        report
            .approved_set
            .lanes
            .notary
            .interfaces
            .consultation_relay_notary
    );
    assert_eq!(
        load_approved_baseline_set_structure(&next_file).expect("updated set round trips"),
        report.approved_set
    );
}

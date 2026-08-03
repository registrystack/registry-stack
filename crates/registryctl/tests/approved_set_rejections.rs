// SPDX-License-Identifier: Apache-2.0

mod approved_set_support;
pub use approved_set_support::{project_authoring, trust, SIGNING_INPUT_MARKER_FILE};

use approved_set_support::approved_set::{
    assemble_initial_approved_set, assemble_updated_approved_set,
    load_approved_baseline_set_structure, AffectedLaneReplacements, ApprovedLaneV1,
    LaneVerificationSourceV1, PortableArtifactLocator, ReviewedBuildUpdateV1,
    VerifiedApprovedLaneV1, APPROVED_BASELINE_SET_SCHEMA_VERSION,
};
use approved_set_support::{
    digest, entry, identity, initial_lane, path_set, replacement_lane, reviewed_binding, verified,
    verifier_for_initial,
};
use registry_platform_config::ProductTrustDomainV1;

fn initial_set(
    temporary: &tempfile::TempDir,
) -> (
    std::path::PathBuf,
    approved_set_support::approved_set::ApprovedBaselineSetV1,
) {
    let path = temporary.path().join("approved-set.json");
    let set =
        assemble_initial_approved_set(&path_set(temporary.path()), &path, verifier_for_initial)
            .expect("initial set assembles")
            .approved_set;
    (path, set)
}

#[test]
fn initial_assembly_rejects_mixed_project_identity_before_output_creation() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let output = temporary.path().join("mixed.json");
    let error = assemble_initial_approved_set(&path_set(temporary.path()), &output, |request| {
        Ok(if request.lane == ApprovedLaneV1::RelayConsultation {
            verified(
                request.lane,
                "other-project",
                "approved",
                1,
                'c',
                None,
                'c',
                'f',
            )
        } else {
            initial_lane(request.lane)
        })
    })
    .expect_err("mixed project must fail");

    assert!(format!("{error:#}").contains("one project and environment"));
    assert!(!output.exists());
}

#[test]
fn independent_verification_rejects_development_trust_for_an_approved_lane() {
    let lane = ApprovedLaneV1::RelayPublic;
    let mut acceptance_identity = identity(lane, "example-project");
    acceptance_identity.trust_domain = ProductTrustDomainV1::Development;

    let error = VerifiedApprovedLaneV1::from_independent_verification(
        lane,
        acceptance_identity,
        1,
        digest('a'),
        None,
        entry(lane, "approved", 'a', 'd'),
    )
    .expect_err("development trust must not enter a governed approved set");

    assert!(format!("{error:#}").contains("governed trust domain"));
}

#[test]
fn update_requires_exact_replacements_and_never_carries_an_unverified_lane() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (preceding_file, _) = initial_set(&temporary);
    let output = temporary.path().join("next.json");
    let reviewed = ReviewedBuildUpdateV1 {
        relay_public: Some(reviewed_binding(ApprovedLaneV1::RelayPublic)),
        relay_consultation: Some(reviewed_binding(ApprovedLaneV1::RelayConsultation)),
    };
    let missing = AffectedLaneReplacements {
        relay_public: None,
        relay_consultation: Some(temporary.path().join("consultation-next")),
    };
    let mut verification_called = false;
    let error =
        assemble_updated_approved_set(&preceding_file, &reviewed, &[], &missing, &output, |_| {
            verification_called = true;
            unreachable!("replacement completeness fails before verification")
        })
        .expect_err("missing affected replacement must fail");
    assert!(format!("{error:#}").contains("exactly match"));
    assert!(!verification_called);
    assert!(!output.exists());

    let complete = AffectedLaneReplacements {
        relay_public: Some(temporary.path().join("public-next")),
        relay_consultation: Some(temporary.path().join("consultation-next")),
    };
    let planted_canary = "CANARY_PRIVATE_PRECEDING_PATH";
    let error = assemble_updated_approved_set(
        &preceding_file,
        &reviewed,
        &[],
        &complete,
        &output,
        |request| match request.source {
            LaneVerificationSourceV1::PrecedingApprovedEntry { .. }
                if request.lane == ApprovedLaneV1::RelayPublic =>
            {
                anyhow::bail!("{planted_canary}")
            }
            LaneVerificationSourceV1::PrecedingApprovedEntry { .. } => {
                Ok(initial_lane(request.lane))
            }
            LaneVerificationSourceV1::LaneDirectory(_) => Ok(replacement_lane(request.lane)),
        },
    )
    .expect_err("unverified carry forward must fail");
    let message = format!("{error:#}");
    assert!(message.contains("preceding-lane verification failed"));
    assert!(!message.contains(planted_canary));
    assert!(!output.exists());
}

#[test]
fn update_rejects_non_successor_lineage_and_reviewed_closure_mismatch() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (preceding_file, _) = initial_set(&temporary);
    let output = temporary.path().join("next.json");
    let reviewed = ReviewedBuildUpdateV1 {
        relay_public: None,
        relay_consultation: Some(reviewed_binding(ApprovedLaneV1::RelayConsultation)),
    };
    let replacements = AffectedLaneReplacements {
        relay_public: None,
        relay_consultation: Some(temporary.path().join("consultation-next")),
    };

    let error = assemble_updated_approved_set(
        &preceding_file,
        &reviewed,
        &[],
        &replacements,
        &output,
        |request| match request.source {
            LaneVerificationSourceV1::PrecedingApprovedEntry { .. } => {
                Ok(initial_lane(request.lane))
            }
            LaneVerificationSourceV1::LaneDirectory(_)
                if request.lane == ApprovedLaneV1::RelayConsultation =>
            {
                Ok(verified(
                    request.lane,
                    "example-project",
                    "approved-next",
                    3,
                    'e',
                    Some('b'),
                    '7',
                    '8',
                ))
            }
            LaneVerificationSourceV1::LaneDirectory(_) => Ok(replacement_lane(request.lane)),
        },
    )
    .expect_err("skipped sequence must fail");
    assert!(format!("{error:#}").contains("does not extend"));
    assert!(!output.exists());

    let mut wrong_reviewed = reviewed.clone();
    wrong_reviewed
        .relay_consultation
        .as_mut()
        .expect("consultation is affected")
        .lane_scoped_reviewed_input_digest = approved_set_support::digest('0');
    let error = assemble_updated_approved_set(
        &preceding_file,
        &wrong_reviewed,
        &[],
        &replacements,
        &output,
        |request| match request.source {
            LaneVerificationSourceV1::PrecedingApprovedEntry { .. } => {
                Ok(initial_lane(request.lane))
            }
            LaneVerificationSourceV1::LaneDirectory(_) => Ok(replacement_lane(request.lane)),
        },
    )
    .expect_err("replacement outside reviewed closure must fail");
    assert!(format!("{error:#}").contains("reviewed build closure"));
    assert!(!output.exists());
}

#[test]
fn update_requires_explicit_anchor_rotation_and_rejects_selected_same_anchor() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (preceding_file, _) = initial_set(&temporary);
    let output = temporary.path().join("next.json");
    let reviewed = ReviewedBuildUpdateV1 {
        relay_consultation: Some(reviewed_binding(ApprovedLaneV1::RelayConsultation)),
        ..Default::default()
    };
    let replacements = AffectedLaneReplacements {
        relay_consultation: Some(temporary.path().join("consultation-next")),
        ..Default::default()
    };
    let same_anchor = assemble_updated_approved_set(
        &preceding_file,
        &reviewed,
        &[ApprovedLaneV1::RelayConsultation],
        &replacements,
        &output,
        |request| match request.source {
            LaneVerificationSourceV1::PrecedingApprovedEntry { .. } => {
                Ok(initial_lane(request.lane))
            }
            LaneVerificationSourceV1::LaneDirectory(_) => Ok(replacement_lane(request.lane)),
        },
    )
    .expect_err("selected rotation must not accept the preceding anchor");
    assert!(format!("{same_anchor:#}").contains("retained its preceding anchor"));
    assert!(!output.exists());

    let implicit_rotation = assemble_updated_approved_set(
        &preceding_file,
        &reviewed,
        &[],
        &replacements,
        &output,
        |request| match request.source {
            LaneVerificationSourceV1::PrecedingApprovedEntry { .. } => {
                Ok(initial_lane(request.lane))
            }
            LaneVerificationSourceV1::LaneDirectory(_) => {
                let preceding_anchor = initial_lane(request.lane).entry().anchor_digest.clone();
                Ok(replacement_lane(request.lane).with_test_anchor_chain(vec![
                    preceding_anchor,
                    approved_set_support::digest('0'),
                ]))
            }
        },
    )
    .expect_err("anchor change without selector must fail");
    assert!(format!("{implicit_rotation:#}").contains("without explicit rotation selection"));
    assert!(!output.exists());
}

#[test]
fn closed_reader_rejects_unknown_fields_and_nonportable_locators() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (approved_file, approved_set) = initial_set(&temporary);
    let mut value = serde_json::to_value(&approved_set).expect("set serializes");
    value["unexpected"] = serde_json::json!(true);
    let unknown = temporary.path().join("unknown.json");
    std::fs::write(
        &unknown,
        serde_json::to_vec(&value).expect("test JSON serializes"),
    )
    .expect("test file writes");
    assert!(load_approved_baseline_set_structure(&unknown).is_err());

    assert!(PortableArtifactLocator::new("/host/private/bundle").is_err());
    assert!(PortableArtifactLocator::new("../other/bundle").is_err());
    assert!(PortableArtifactLocator::new("C:\\private\\bundle").is_err());
    assert!(PortableArtifactLocator::new("https://example.invalid/bundle").is_err());

    let oversized = temporary.path().join("oversized.json");
    std::fs::write(
        &oversized,
        vec![
            b' ';
            approved_set_support::approved_set::MAX_APPROVED_BASELINE_SET_BYTES as usize + 1
        ],
    )
    .expect("oversized input writes");
    assert!(load_approved_baseline_set_structure(&oversized).is_err());
    assert!(load_approved_baseline_set_structure(&approved_file).is_ok());
}

#[test]
fn assembly_preserves_an_existing_output_file() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let output = temporary.path().join("approved-set.json");
    std::fs::write(&output, b"operator-owned").expect("existing output writes");
    let mut verification_called = false;
    let error = assemble_initial_approved_set(&path_set(temporary.path()), &output, |_| {
        verification_called = true;
        unreachable!("existing output fails before verification")
    })
    .expect_err("existing output must fail");

    assert!(format!("{error:#}").contains("already exists"));
    assert!(!verification_called);
    assert_eq!(
        std::fs::read(&output).expect("existing output reads"),
        b"operator-owned"
    );
}

/// The approved-set schema version issued before Registry Notary was retired.
const PRE_RETIREMENT_SCHEMA_VERSION: &str = "1.0";

/// The exact refusal an operator holding a pre-retirement approved set reads.
const PRE_RETIREMENT_REFUSAL: &str = "approved set predates the Registry Notary retirement: Registry Notary is retired, so a schema version 1.0 approved set, its notary lane, and the cross-lane interface digests it binds are no longer verified; this reader refuses the document rather than honor an approval whose integrity claim is no longer enforced, so re-approve the baseline to issue a schema version 2.0 approved set";

fn write_test_json(path: &std::path::Path, value: &serde_json::Value) {
    std::fs::write(
        path,
        serde_json::to_vec(value).expect("test JSON serializes"),
    )
    .expect("test file writes");
}

#[test]
fn reader_refuses_a_pre_retirement_approved_set_with_an_actionable_message() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (_, approved_set) = initial_set(&temporary);
    let mut value = serde_json::to_value(&approved_set).expect("set serializes");
    value["schema_version"] = serde_json::json!(PRE_RETIREMENT_SCHEMA_VERSION);
    let pre_retirement = temporary.path().join("pre-retirement.json");
    write_test_json(&pre_retirement, &value);

    let error = load_approved_baseline_set_structure(&pre_retirement)
        .expect_err("a pre-retirement approved set must be refused");
    assert_eq!(format!("{error:#}"), PRE_RETIREMENT_REFUSAL);
}

#[test]
fn reader_refuses_retired_notary_material_rather_than_reporting_an_unknown_field() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (_, approved_set) = initial_set(&temporary);

    let mut with_interfaces = serde_json::to_value(&approved_set).expect("set serializes");
    with_interfaces["lanes"]["relay-consultation"]["interfaces"] =
        serde_json::json!({ "consultation_relay_notary": digest('a') });
    let interfaces_file = temporary.path().join("interfaces.json");
    write_test_json(&interfaces_file, &with_interfaces);
    let error = load_approved_baseline_set_structure(&interfaces_file)
        .expect_err("a retired interface digest binding must be refused");
    let message = format!("{error:#}");
    assert_eq!(message, PRE_RETIREMENT_REFUSAL);
    assert!(!message.contains("unknown field"), "{message}");

    let mut with_notary_lane = serde_json::to_value(&approved_set).expect("set serializes");
    with_notary_lane["lanes"]["notary"] = with_notary_lane["lanes"]["relay-public"].clone();
    let notary_file = temporary.path().join("notary-lane.json");
    write_test_json(&notary_file, &with_notary_lane);
    let error = load_approved_baseline_set_structure(&notary_file)
        .expect_err("a retired notary lane must be refused");
    let message = format!("{error:#}");
    assert_eq!(message, PRE_RETIREMENT_REFUSAL);
    assert!(!message.contains("unknown field"), "{message}");
}

#[test]
fn in_memory_validation_names_the_retirement_for_the_pre_retirement_version() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (_, mut approved_set) = initial_set(&temporary);
    approved_set.schema_version = PRE_RETIREMENT_SCHEMA_VERSION.to_string();

    let error = approved_set
        .validate()
        .expect_err("the pre-retirement schema version must be refused");
    assert_eq!(error.to_string(), PRE_RETIREMENT_REFUSAL);
}

#[test]
fn a_current_approved_set_still_round_trips_and_validates() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (approved_file, approved_set) = initial_set(&temporary);

    assert_ne!(
        APPROVED_BASELINE_SET_SCHEMA_VERSION, PRE_RETIREMENT_SCHEMA_VERSION,
        "the retirement must not reuse the schema version it invalidated"
    );
    assert_eq!(
        approved_set.schema_version,
        APPROVED_BASELINE_SET_SCHEMA_VERSION
    );
    let loaded =
        load_approved_baseline_set_structure(&approved_file).expect("a current approved set loads");
    assert_eq!(loaded, approved_set);
    loaded.validate().expect("a current approved set validates");
}

#[cfg(unix)]
#[test]
fn approved_set_reader_does_not_follow_a_symbolic_link() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let (approved_file, _) = initial_set(&temporary);
    let link = temporary.path().join("approved-link.json");
    symlink(approved_file, &link).expect("test symlink creates");
    assert!(load_approved_baseline_set_structure(&link).is_err());
}

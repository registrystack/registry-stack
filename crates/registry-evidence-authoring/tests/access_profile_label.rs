//! An access profile may carry a `label` and a `description` for reviewer
//! views. Neither takes part in matching a caller.
#![allow(
    clippy::disallowed_macros,
    reason = "this test target embeds the public canonical fixtures; the library performs no I/O"
)]

use registry_evidence_authoring::{
    project::{self, EvidenceProject},
    target::{self, EvidenceTargetAuthority},
};
use registry_platform_yaml::{Decoded, Report};

const PROJECT: &str = include_str!("../../../products/evidence/examples/standalone/evidence.yaml");
const AUTHORITY: &str =
    include_str!("../../../products/evidence/examples/standalone/dev-authority.yaml");
const PROFILE_HEADER: &str = "  standalone-service:\n";

fn project() -> EvidenceProject {
    project::read_project("evidence.yaml", PROJECT.as_bytes())
        .expect("example project reads")
        .value
}

fn read_with(profile_members: &str) -> Result<Decoded<EvidenceTargetAuthority>, Report> {
    let text = AUTHORITY.replacen(
        PROFILE_HEADER,
        &format!("{PROFILE_HEADER}{profile_members}"),
        1,
    );
    assert_ne!(text, AUTHORITY, "the example names the profile");
    target::read_authority("dev-authority.yaml", text.as_bytes(), &project())
}

#[test]
fn an_access_profile_reads_a_label_and_a_description() {
    let decoded = read_with(
        "    label: Standalone service\n    description: Requests evidence for the standalone example.\n",
    )
    .expect("the labelled profile reads");
    let profile = decoded.value.access_profiles.values().next().unwrap();
    assert_eq!(profile.label.as_deref(), Some("Standalone service"));
    assert_eq!(
        profile.description.as_deref(),
        Some("Requests evidence for the standalone example.")
    );
}

#[test]
fn an_access_profile_without_a_label_still_reads() {
    let decoded = target::read_authority("dev-authority.yaml", AUTHORITY.as_bytes(), &project())
        .expect("the example reads");
    let profile = decoded.value.access_profiles.values().next().unwrap();
    assert_eq!(profile.label, None);
    assert_eq!(profile.description, None);
}

#[test]
fn a_label_with_a_bidirectional_override_is_refused() {
    let report = read_with("    label: \"a\\u202eb\"\n")
        .expect_err("a label with a bidirectional override is refused");
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.path == "/accessProfiles/standalone-service/label"),
        "{report:?}"
    );
}

#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

use registry_breg::compiler::{CompileProfile, compile_project};
use registry_breg::contract::parse_project_yaml;

const STARTERS: [(&[u8], &[u8]); 4] = [
    (
        include_bytes!("../../../products/breg/starters/public-organizations/core/registry.yaml"),
        include_bytes!(
            "../../../products/breg/starters/public-organizations/core/tests/journeys.yaml"
        ),
    ),
    (
        include_bytes!("../../../products/breg/starters/agricultural-holdings/core/registry.yaml"),
        include_bytes!(
            "../../../products/breg/starters/agricultural-holdings/core/tests/journeys.yaml"
        ),
    ),
    (
        include_bytes!("../../../products/breg/starters/professional-licences/core/registry.yaml"),
        include_bytes!(
            "../../../products/breg/starters/professional-licences/core/tests/journeys.yaml"
        ),
    ),
    (
        include_bytes!("../../../products/breg/starters/seed-lots/core/registry.yaml"),
        include_bytes!("../../../products/breg/starters/seed-lots/core/tests/journeys.yaml"),
    ),
];

#[test]
#[ignore = "Public starter catalog migration is explicitly deferred; native canonical replacement: refactor_contract::immediate_mode_cannot_bypass_target_proposal_policy"]
fn published_starters_compile_with_reviewed_update_policy() {
    for (source, _) in STARTERS {
        let project = parse_project_yaml(source).expect("starter source parses");
        compile_project(&project, &[], CompileProfile::Production).expect("starter compiles");
        let mut changed: serde_norway::Value = serde_norway::from_slice(source).unwrap();
        let editor = changed["accessProfiles"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|profile| profile["id"] == "editor")
            .unwrap();
        editor["permissions"]["records"][0]["operations"]
            .as_sequence_mut()
            .unwrap()
            .push("patch".into());
        let changed = parse_project_yaml(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            compile_project(&changed, &[], CompileProfile::Production).is_err(),
            "reviewed primary records must reject direct PATCH grants"
        );
    }
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
#[ignore = "Public starter catalog migration is explicitly deferred; native canonical replacement: fixture_tooling::fixture_tooling_crud_fields_accept_public_names_without_alias_overwrite"]
fn published_starter_journeys_resolve_declared_fields_profiles_and_typed_aliases() {
    for ((source, journeys), security) in STARTERS.into_iter().zip([
        include_bytes!("../../../products/breg/starters/public-organizations/core/tests/security-journeys.yaml").as_slice(),
        include_bytes!("../../../products/breg/starters/agricultural-holdings/core/tests/security-journeys.yaml").as_slice(),
        include_bytes!("../../../products/breg/starters/professional-licences/core/tests/security-journeys.yaml").as_slice(),
        include_bytes!("../../../products/breg/starters/seed-lots/core/tests/security-journeys.yaml").as_slice(),
    ]) {
        let project = parse_project_yaml(source).expect("starter source parses");
        let registry = compile_project(&project, &[], CompileProfile::Production).unwrap();
        registry_breg::fixtures::validate_fixture_journeys(journeys, &registry)
            .expect("starter journey preflight passes");
        registry_breg::fixtures::validate_fixture_journeys(security, &registry)
            .expect("security journey preflight passes");
    }
}

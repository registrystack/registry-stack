// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_yaml, Operation, RequestVisibilitySource};

fn acceptance_project() -> registry_breg::contract::RegistryProject {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/asset-site-placement-change-requests/registry.yaml");
    let bytes = fs::read(path).expect("change-request acceptance project is readable");
    parse_project_yaml(&bytes).expect("change-request acceptance project parses")
}

#[test]
fn owner_request_visibility_compiles_to_a_fail_closed_rls_boundary() {
    let compiled = compile_project(&acceptance_project(), &[], CompileProfile::Authoring)
        .expect("owner-scoped request visibility compiles");
    let profile = &compiled.entities()["placement-correction-request"].access_profiles
        ["correction-submitter"];
    assert_eq!(
        profile.request_visibility,
        Some(RequestVisibilitySource::Owner)
    );
    let ddl = compiled.ddl().script();
    assert!(ddl.contains("registry.request_owner_reference"));
    assert!(ddl.contains("cr_visibility.owner_reference"));
    assert!(ddl.contains("registry.created_record_id"));
}

#[test]
fn owner_request_visibility_is_rejected_outside_authenticated_request_reads() {
    let mut non_request = acceptance_project();
    let site_planner = non_request
        .access_profiles
        .iter_mut()
        .find(|profile| profile.id == "site-planner")
        .expect("site planner exists");
    site_planner
        .grants
        .iter_mut()
        .find(|grant| grant.entity == "asset-item")
        .expect("asset item grant exists")
        .request_visibility = Some(RequestVisibilitySource::Owner);
    let failure = compile_project(&non_request, &[], CompileProfile::Authoring)
        .expect_err("ordinary entities cannot claim request ownership visibility");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access_profile.request_visibility.invalid"));

    let mut write_only = acceptance_project();
    let submitter = write_only
        .access_profiles
        .iter_mut()
        .find(|profile| profile.id == "correction-submitter")
        .expect("correction submitter exists");
    let grant = submitter
        .grants
        .iter_mut()
        .find(|grant| grant.entity == "placement-correction-request")
        .expect("request grant exists");
    grant.operations.remove(&Operation::Get);
    grant.operations.remove(&Operation::List);
    let failure = compile_project(&write_only, &[], CompileProfile::Authoring)
        .expect_err("owner visibility without a read operation is meaningless");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access_profile.request_visibility.invalid"));
}

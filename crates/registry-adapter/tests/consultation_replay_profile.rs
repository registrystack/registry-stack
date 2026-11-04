// SPDX-License-Identifier: Apache-2.0

//! Offline regression for the built-in GovStack Consultation replay target.
//! A caller-supplied generic profile cannot replace its fixed wire contract.

use std::path::{Path, PathBuf};

use registry_adapter::engine::load::read_artifact;
use registry_adapter::govstack::consultation::built_in_profile;
use registry_adapter::replay_serve::run_with_project_directory;
use registry_adapter_core::{
    AdapterFixture, AdapterPack, AdapterProfile, AdapterProject, ADAPTER_FIXTURE_API_VERSION,
    ADAPTER_FIXTURE_KIND, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND, ADAPTER_PROJECT_API_VERSION,
    ADAPTER_PROJECT_KIND,
};
use serde_json::json;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[tokio::test]
async fn consultation_replay_ignores_a_caller_supplied_response_profile() {
    let root = repository();
    let project_directory = root.join("products/adapter/examples/dhis2-consultation");
    let pack_path = root.join("products/adapter/packs/dhis2-tracker/pack.yaml");

    let (project, _): (AdapterProject, _) = read_artifact(
        &project_directory.join("project.yaml"),
        ADAPTER_PROJECT_KIND,
        ADAPTER_PROJECT_API_VERSION,
    )
    .expect("the maintained Consultation project reads");
    let (pack, _): (AdapterPack, _) =
        read_artifact(&pack_path, ADAPTER_PACK_KIND, ADAPTER_PACK_API_VERSION)
            .expect("the maintained DHIS2 pack reads");
    let (fixture, _): (AdapterFixture, _) = read_artifact(
        &project_directory.join("fixtures/retrieve-public.yaml"),
        ADAPTER_FIXTURE_KIND,
        ADAPTER_FIXTURE_API_VERSION,
    )
    .expect("the maintained Retrieve fixture reads");

    let mut supplied =
        serde_json::to_value(built_in_profile()).expect("the fixed profile serializes");
    let retrieve = supplied["operations"]
        .as_array_mut()
        .expect("profile operations")
        .iter_mut()
        .find(|operation| operation["id"] == "retrieve")
        .expect("the Retrieve operation");
    retrieve["itemEnvelope"] =
        json!(r#"{"callerSuppliedId":"{{recordId}}","callerSuppliedData":{{record}}}"#);
    retrieve["responseEnvelope"] = json!(r#"{"callerSupplied":{{record}}}"#);
    let supplied: AdapterProfile =
        serde_json::from_value(supplied).expect("the caller-supplied profile remains valid");

    let replay = run_with_project_directory(
        &project,
        &supplied,
        &pack,
        pack_path.parent().expect("the pack directory"),
        &project_directory,
        &fixture,
        0,
    )
    .await
    .expect("the maintained Retrieve fixture replays offline");

    assert_eq!(replay.status, 200);
    let body = replay.body.expect("Retrieve returns a response body");
    assert_eq!(
        body,
        json!({
            "recordId": "EeBJ3Sn9uLg",
            "data": {
                "source": {
                    "id": "EeBJ3Sn9uLg",
                    "type": "cQWYtUfH6Vx"
                },
                "registration": {
                    "organisationUnit": "slSrf7H9lMf",
                    "createdAt": "2017-01-20T10:44:02.770",
                    "updatedAt": "2017-05-26T11:46:22.372"
                }
            }
        })
    );
    let public = body.to_string();
    assert!(!public.contains("callerSupplied"), "{public}");
    assert!(!public.contains("PRIVATE-CANARY"), "{public}");
}

// SPDX-License-Identifier: Apache-2.0

//! The SFTP source's operator configuration is closed and fail-closed before
//! the job host opens a socket or resolves a credential.

#![cfg(feature = "job-sftp")]

use registry_adapter_engine::job_sources::JobRuntimeConfig;

fn load(source: serde_json::Value) -> Result<JobRuntimeConfig, String> {
    let scratch = tempfile::tempdir().expect("the runtime scratch directory");
    let path = scratch.path().join("job-runtime.json");
    let document = serde_json::json!({
        "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
        "kind": "AdapterJobRuntimeConfig",
        "id": "sftp-config-test",
        "endpoints": [],
        "sources": { "sftp": { "dropbox": source } },
        "allowedPrivateCidrs": ["127.0.0.0/8"]
    });
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("the runtime document renders"),
    )
    .expect("the runtime document is written");
    JobRuntimeConfig::load(&path).map_err(|error| error.to_string())
}

fn source() -> serde_json::Value {
    serde_json::json!({
        "host": "127.0.0.1",
        "port": 22,
        "user": "source-reader",
        "baseDirectory": "/ready",
        "pinnedHostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogusButShapeCheckedAtActivation",
        "credential": {
            "type": "password",
            "passwordRef": "secret:env/SFTP_SOURCE_PASSWORD"
        },
        "namespace": "submissions",
        "include": "*.csv",
        "completion": {
            "type": "done-file",
            "name": "$simple{file:name}.done"
        },
        "maximumListingEntries": 500
    })
}

#[test]
fn sftp_requires_one_explicit_completion_convention() {
    assert!(load(source()).is_ok());

    let mut missing = source();
    missing
        .as_object_mut()
        .expect("the source object")
        .remove("completion");
    assert!(load(missing).is_err());

    let mut contradictory = source();
    contradictory["completion"] = serde_json::json!({
        "type": "completed-name",
        "producerAtomicHandover": false
    });
    assert!(load(contradictory).is_err());
}

#[test]
fn sftp_refuses_a_relative_or_non_normal_base_directory() {
    for directory in [
        "ready",
        "//ready",
        "/ready//nested",
        "/ready/../outside",
        "/ready/./nested",
        "/ready\\nested",
    ] {
        let mut candidate = source();
        candidate["baseDirectory"] = serde_json::Value::String(directory.to_owned());
        assert!(load(candidate).is_err(), "refused {directory}");
    }

    for directory in ["/", "/ready"] {
        let mut candidate = source();
        candidate["baseDirectory"] = serde_json::Value::String(directory.to_owned());
        assert!(load(candidate).is_ok(), "accepted {directory}");
    }
}

#[test]
fn sftp_listing_bound_is_reader_checked() {
    for value in [0_u64, 10_001] {
        let mut candidate = source();
        candidate["maximumListingEntries"] = serde_json::json!(value);
        assert!(load(candidate).is_err(), "refused {value}");
    }
}

#[test]
fn sftp_done_file_name_is_bounded_before_transport() {
    let mut candidate = source();
    candidate["completion"]["name"] = serde_json::Value::String("x".repeat(1_025));
    assert!(load(candidate).is_err());
}

#[test]
fn sftp_include_glob_is_bounded_before_listing() {
    let mut maximum = source();
    maximum["include"] = serde_json::Value::String(format!("{}??", "é".repeat(511)));
    assert!(load(maximum).is_ok(), "a 1024-byte pattern is accepted");

    let mut oversized = source();
    oversized["include"] = serde_json::Value::String("*".repeat(1_025));
    assert!(load(oversized).is_err());

    let mut control = source();
    control["include"] = serde_json::Value::String("*.csv\n".to_owned());
    assert!(load(control).is_err());
}

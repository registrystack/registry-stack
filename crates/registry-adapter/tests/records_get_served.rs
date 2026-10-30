// SPDX-License-Identifier: Apache-2.0

//! The served `records-get` slice, end to end: the built `adapter` binary
//! starts on the dhis2-tracker example with a runtime config, a loopback
//! upstream replays the committed captures, and a facade call comes back
//! shaped, as the not-found problem, or refused before any upstream
//! call. Needs `ADAPTER_TEST_DATABASE_URL` (the journal is written before
//! every answer); without it every test fails on the spot.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::json;
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, expected_basic, Served};

#[tokio::test]
async fn a_found_record_comes_back_shaped_through_the_served_binary() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));

    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({
            "data": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "slSrf7H9lMf",
                "created_at": "2017-01-20T10:44:02.770",
                "updated_at": "2017-05-26T11:46:22.372"
            },
            "meta": {
                "registryIdentifier": "dhis2-tracker-registry",
                "datasetIdentifier": "persons",
                "entityTypeIdentifier": "person"
            }
        })
    );
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].target,
        "/api/tracker/trackedEntities/EeBJ3Sn9uLg"
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some(expected_basic().as_str())
    );
    let kinds = served.journal_kinds().await;
    assert!(
        kinds.iter().any(|kind| kind == "exchangeCompleted"),
        "{kinds:?}"
    );
}

#[tokio::test]
async fn a_missing_record_is_the_not_found_problem() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-missing");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person/TV7SRzsjKQi", Some(&token));

    assert_eq!(status, 404, "{body}");
    assert_eq!(body["code"], "source.not-found");
    assert_eq!(body["status"], 404);
    assert_eq!(
        body["detail"],
        "No tracked entity with that identifier exists at the source."
    );
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn a_request_without_a_valid_token_is_refused_before_any_upstream_call() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let (status, head, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", None);
    assert_eq!(status, 401, "{body}");
    assert!(head
        .to_ascii_lowercase()
        .contains("www-authenticate: bearer"));

    let (status, _, _) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some("not.a.token"));
    assert_eq!(status, 401);

    let forged = Served::forged_token();
    let (status, _, _) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&forged));
    assert_eq!(status, 401);

    let unscoped = served.token("records.write");
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&unscoped));
    assert_eq!(status, 403, "{body}");

    assert_eq!(
        upstream.request_count(),
        0,
        "no refused call reached the upstream"
    );
}

#[tokio::test]
async fn a_dot_segment_record_identifier_never_reaches_the_upstream() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    for spelling in ["..", "%2E%2E", "%2e%2e", ".", "%2E", ".%2e"] {
        let (status, _, body) = served.get(&format!("/v1/records/person/{spelling}"), Some(&token));
        assert_eq!(status, 400, "{spelling}: {body}");
        assert_eq!(body["code"], "source.facade", "{spelling}");
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "no dot segment was sent upstream"
    );
}

#[tokio::test]
async fn a_token_from_an_unlisted_client_is_refused_before_any_upstream_call() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let stranger = served.token_with("subject", "records.read", json!({"client_id": "stranger"}));
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&stranger));
    assert_eq!(status, 401, "{body}");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn an_exchanged_token_is_refused_because_no_assertion_authority_is_declared() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let exchanged = served.token_with(
        "subject",
        "records.read",
        json!({registry_platform_oidc::ASSERTION_ISSUER_CLAIM: "https://other.example.invalid"}),
    );
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&exchanged));
    assert_eq!(status, 401, "{body}");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_subject_the_journal_cannot_hold_is_refused_at_authentication() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    for subject in ["s".repeat(257), "nul\u{0}subject".to_owned()] {
        let token = served.token_for(&subject, "records.read");
        let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
        assert_eq!(status, 401, "{body}");
    }
    let ok = served.token_for(&"s".repeat(256), "records.read");
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&ok));
    assert_eq!(status, 200, "{body}");
}

/// The served example folder holds no pack, profile or scripts, so every
/// test that starts over it proves the serve flags resolve the maintained
/// artifacts rather than files beside the project.
#[tokio::test]
async fn the_example_folder_is_served_with_its_pack_and_profile_by_flag() {
    let folder = Served::example_project();
    for beside in ["pack.yaml", "profile.yaml", "scripts"] {
        assert!(
            !folder.join(beside).exists(),
            "{beside} sits beside the project"
        );
    }
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 200, "{body}");
}

fn copy_example_project(directory: &std::path::Path) {
    fn copy(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir_all(to).expect("create the copy directory");
        for entry in std::fs::read_dir(from).expect("read the example directory") {
            let entry = entry.expect("a directory entry");
            let target = to.join(entry.file_name());
            if entry.file_type().expect("a file type").is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).expect("copy a file");
            }
        }
    }
    copy(&Served::example_project(), directory);
    // The example folder holds only the project: the copy carries its own
    // pack, scripts and profile beside it, so a test can edit them.
    let packs = Served::example_pack();
    copy(packs.parent().expect("the pack directory"), directory);
    std::fs::copy(Served::example_profile(), directory.join("profile.yaml"))
        .expect("copy the profile");
}

/// A copy of the example project whose fetch route has no shaping step, so
/// the route ends with the source's own body; the pack digest pin in the
/// copied project is re-pinned to the edited bytes.
fn project_without_the_shaping_step(directory: &std::path::Path) {
    use sha2::{Digest, Sha256};
    fn digest_of(bytes: &[u8]) -> String {
        let hex: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("sha256:{hex}")
    }
    copy_example_project(directory);
    let pack_path = directory.join("pack.yaml");
    let pack = std::fs::read_to_string(&pack_path).expect("the pack is readable");
    let step = "      - setBody:\n          rhai:\n            file: scripts/to-record.rhai\n            entrypoint: to_record\n  - id: import-tracked-entity";
    assert!(
        pack.contains(step),
        "the shaping step is where the test expects it"
    );
    let edited = pack.replacen(step, "  - id: import-tracked-entity", 1);
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the project is readable");
    let pinned = digest_of(pack.as_bytes());
    assert!(
        project.contains(&pinned),
        "the project pins the committed pack"
    );
    let repinned = digest_of(edited.as_bytes());
    std::fs::write(&pack_path, edited).expect("write the edited pack");
    std::fs::write(&project_path, project.replace(&pinned, &repinned))
        .expect("write the re-pinned project");
}

#[tokio::test]
async fn a_source_body_with_undeclared_fields_is_never_disclosed() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    project_without_the_shaping_step(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));

    assert_eq!(status, 500, "{body}");
    assert_eq!(body["code"], "source.disclosure", "{body}");
    let text = body.to_string();
    assert!(
        !text.contains("slSrf7H9lMf") && !text.contains("cQWYtUfH6Vx"),
        "no source value reaches the caller: {text}"
    );
    let kinds = served.journal_kinds().await;
    assert!(
        kinds.contains(&"exchangeFailed".to_owned())
            && !kinds.contains(&"exchangeCompleted".to_owned()),
        "{kinds:?}"
    );
}

#[tokio::test]
async fn a_verified_caller_refused_by_scope_or_record_type_is_journaled_without_values() {
    let upstream = UpstreamDouble::start();
    let served = Served::start(&upstream.url("")).await;

    let unscoped = served.token("records.write");
    let (status, _, _) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&unscoped));
    assert_eq!(status, 403);
    let token = served.token("records.read");
    let (status, _, _) = served.get("/v1/records/canary-type/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 404);

    let details = served.journal_details("callRefused").await;
    assert_eq!(
        details,
        vec![
            json!({ "class": "facade.forbidden", "status": 403 }),
            json!({ "class": "facade.not-found", "status": 404 }),
        ]
    );
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn an_exchange_finishes_and_journals_when_the_caller_disconnects() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    upstream.delay_answers(std::time::Duration::from_millis(800));
    let served = Served::start(&upstream.url("")).await;

    let token = served.token("records.read");
    served.get_and_disconnect("/v1/records/person/EeBJ3Sn9uLg", &token);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let kinds = served.journal_kinds().await;
        if kinds.contains(&"exchangeCompleted".to_owned()) {
            assert!(kinds.contains(&"exchangeCreated".to_owned()), "{kinds:?}");
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the exchange never completed: {kinds:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_script_that_fails_its_pinned_digest_refuses_startup() {
    let upstream = UpstreamDouble::start();
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    let script = directory.path().join("scripts/to-record.rhai");
    let mut text = std::fs::read_to_string(&script).expect("the script is readable");
    text.push_str("\n// changed after the pack pinned it\n");
    std::fs::write(&script, text).expect("write the changed script");

    let stderr = Served::refusal_with_project(&upstream.url(""), directory.path()).await;

    assert!(
        stderr.contains("does not match its pinned digest"),
        "the refusal names its cause: {stderr}"
    );
}

#[tokio::test]
async fn an_unusable_cursor_key_refuses_startup_before_the_listener_opens() {
    let upstream = UpstreamDouble::start();

    let stderr =
        Served::refusal_with_cursor_key(&upstream.url(""), &Served::example_project(), "too-short")
            .await;

    assert!(stderr.contains("cursor key"), "{stderr}");
}

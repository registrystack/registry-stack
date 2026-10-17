// SPDX-License-Identifier: Apache-2.0
use super::*;

async fn peer_metadata(server: &MockServer, version: Option<&str>, malformed: bool) {
    let mut metadata = json!({
        "metadataVersion":"2", "id":"registry", "version":"1", "revision":DIGEST,
        "recordTypes":[], "operations":[],
        "proposals":{"method":"GET","path":"/v1/proposals","accessProfiles":[],
            "get":{"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":[]},
            "actions":[{"actionId":"correct-address","accessProfile":"reviewer",
                "operations":["get-review-context"],"readableInputs":[]}]}
    });
    if malformed {
        metadata.as_object_mut().unwrap().remove("recordTypes");
    }
    let mut reply = ResponseTemplate::new(200)
        .insert_header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .insert_header("cache-control", "no-store")
        .insert_header("vary", "authorization, accept")
        .set_body_json(metadata);
    if let Some(version) = version {
        reply = reply.insert_header("registry-engine-version", version);
    }
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(query_param("accessProfile", "reviewer"))
        .and(header("authorization", "Bearer human-bearer"))
        .respond_with(reply)
        .with_priority(1)
        .mount(server)
        .await;
}

async fn read_peer(
    version: Option<&str>,
    malformed: bool,
) -> (
    Result<HumanDisplayObservation, ReviewContextError>,
    Vec<wiremock::Request>,
) {
    let server = MockServer::start().await;
    let export = export();
    let identity = identity(&export);
    let provider = provider(&server, export);
    mocks(&server, "reviewer", "human-bearer", true, DIGEST).await;
    peer_metadata(&server, version, malformed).await;
    let result = provider
        .human_display(HumanDisplayRequest {
            identity: &identity,
            source_profile_id: "reviewer",
            credential: EphemeralCredential::new("human-bearer"),
        })
        .await;
    (result, server.received_requests().await.unwrap())
}

#[tokio::test]
async fn matching_build_version_releases_the_exact_human_projection() {
    let (result, requests) =
        read_peer(Some(registry_platform_buildinfo::DISPLAY_VERSION), false).await;
    assert_eq!(result.unwrap().fields["reference"], json!("REF-42"));
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.headers.get("authorization").unwrap() == "Bearer human-bearer"));
}

#[tokio::test]
async fn mismatched_peer_version_is_named_before_any_subject_read() {
    let (result, requests) = read_peer(Some("999.0.0"), false).await;
    let error = result.expect_err("a different peer release must be refused");
    assert!(error.to_string().contains("version"), "{error}");
    assert_eq!(
        requests.len(),
        1,
        "mismatch must stop before subject disclosure"
    );
}

#[tokio::test]
async fn peer_version_mismatch_takes_precedence_over_required_member_decode_failure() {
    let (result, requests) = read_peer(Some("999.0.0"), true).await;
    let error = result.expect_err("mismatched metadata must be refused by version");
    assert!(error.to_string().contains("version"), "{error}");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn missing_or_malformed_peer_version_refuses_before_subject_disclosure() {
    for version in [None, Some("0.1.0 (canary)"), Some("not-a-version")] {
        let (result, requests) = read_peer(version, false).await;
        let error = result.expect_err("unverified peer version must not release fields");
        assert!(error.to_string().contains("version"), "{error}");
        assert!(!error.to_string().contains("canary"));
        assert_eq!(requests.len(), 1);
    }
}

#[tokio::test]
async fn matching_version_does_not_hide_a_required_member_decode_failure() {
    let (result, requests) =
        read_peer(Some(registry_platform_buildinfo::DISPLAY_VERSION), true).await;
    assert_eq!(result.unwrap_err(), ReviewContextError::Invalid);
    assert_eq!(requests.len(), 1);
}

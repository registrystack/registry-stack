// SPDX-License-Identifier: Apache-2.0
use registry_casework_client::{submission_digest, ReviewCreateRequest};

#[test]
fn bindings_share_the_canonical_unicode_submission_digest() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/submission-digest.json")).unwrap();
    let request: ReviewCreateRequest = serde_json::from_value(fixture["request"].clone()).unwrap();
    let digest = submission_digest(
        fixture["producer"].as_str().unwrap(),
        fixture["sourceNamespace"].as_str().unwrap(),
        &request,
    )
    .unwrap();
    assert_eq!(
        digest.as_str(),
        fixture["expectedSubmissionDigest"].as_str().unwrap()
    );
}

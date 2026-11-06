// SPDX-License-Identifier: Apache-2.0
//! A run snapshot this version refuses to restore: the review-wait fixture
//! whose review cancel names a literal request instead of the request the run
//! submitted, as a package checked by an earlier version could.
use registry_coordinator::definition::Definition;

/// The restore finding the snapshot from [`not_run_owned`] is refused with.
pub const FINDING: &str = "definition.review-request-not-run-owned";

/// The canonical review-wait snapshot with its review cancel retargeted at a
/// literal request.
pub fn not_run_owned() -> String {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("workflow.yaml"),
        include_str!("../fixtures/review-wait/workflow.yaml"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("functions.rhai"),
        include_str!("../fixtures/review-wait/functions.rhai"),
    )
    .unwrap();
    let snapshot = Definition::load(root.path()).unwrap().snapshot().unwrap();
    let owned = r#""request":{"step":"submit-review","type":"step"}"#;
    assert_eq!(snapshot.matches(owned).count(), 1, "{snapshot}");
    let refused = snapshot.replacen(
        owned,
        r#""request":{"type":"literal","value":{"policy":{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","id":"application-review","version":"1"},"requestId":"00000000-0000-4000-8000-000000000010","subject":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":"00000000-0000-4000-8000-000000000001","source":"applications","type":"application","version":"3"},"submissionDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}"#,
        1,
    );
    let Err(refusal) = Definition::from_snapshot(&refused) else {
        panic!("a snapshot that cancels a foreign review request restored");
    };
    assert_eq!(refusal.code, FINDING, "{refusal:?}");
    refused
}

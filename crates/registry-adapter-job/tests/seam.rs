// SPDX-License-Identifier: Apache-2.0

//! The destination seam and the projection, over the compiled engine
//! path: the fixture receiver's scripted answers map onto the seam's
//! outcomes, the deliverable carries exactly the declared projection and
//! nothing more, a re-delivery of the same item sends identical bytes,
//! and no credential ever crosses the seam. These tests run without a
//! database; the store-side pass edges run in the `postgres-test`
//! suite.

#[path = "support/job_fixture.rs"]
mod job_fixture;

#[path = "support/fixture_receiver.rs"]
mod fixture_receiver;

use fixture_receiver::{FixtureReceiver, Scripted};
use job_fixture::{reply_page, JobFixture};
use registry_adapter::engine::job::{compile_job, run_job_page};
use registry_adapter_core::JobIdentity;
use registry_adapter_job::destination::{
    DeliverableItem, FixtureDestination, HandOffOutcome, JobDestination, DESTINATION_UNREACHABLE,
};
use registry_adapter_job::projection;
use serde_json::{json, Value};
use std::time::Duration;

fn job_identity() -> JobIdentity {
    JobIdentity {
        id: "case-daily".parse().expect("a local id"),
        version: "1".to_string(),
    }
}

fn deliverable(projected: Value) -> DeliverableItem {
    DeliverableItem {
        key: "submissions/a".to_string(),
        sequence: 1,
        digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        prior_run_id: None,
        admitted_before: false,
        projected,
    }
}

/// A refused answer maps onto the seam's refusal, and the receiver saw
/// exactly the eight deliverable members with only the projected fields.
#[tokio::test]
async fn a_refused_answer_maps_onto_the_seam_refusal() {
    let receiver = FixtureReceiver::start(vec![Scripted::Refuse {
        code: "schema.required".to_string(),
    }])
    .await;
    let destination = FixtureDestination::new(&receiver.url).expect("a loopback receiver");
    let projected = json!({"id": "a", "answers.age": "045"});
    let outcome = destination
        .deliver(&job_identity(), &deliverable(projected.clone()))
        .await;
    assert_eq!(
        outcome,
        HandOffOutcome::Refused {
            code: "schema.required".to_string()
        }
    );
    let delivery = &receiver.requests()[0];
    let body: Value = serde_json::from_str(&delivery.body_text()).expect("the body parses");
    let members = body.as_object().expect("the body is an object");
    assert_eq!(
        members.len(),
        8,
        "the deliverable carries exactly its eight members, no more: {members:?}"
    );
    for member in [
        "jobId",
        "jobVersion",
        "key",
        "sequence",
        "digest",
        "priorRunId",
        "admittedBefore",
        "projected",
    ] {
        assert!(
            members.contains_key(member),
            "the deliverable carries {member}"
        );
    }
    assert_eq!(
        members["projected"], projected,
        "the seam receives the declared projection and nothing more"
    );
    assert_eq!(members["jobId"], "case-daily");
    assert_eq!(members["sequence"], 1);
}

/// A stopped answer maps onto the pass stop, and an acknowledged answer
/// carries the destination's reference through.
#[tokio::test]
async fn the_stop_and_acknowledged_answers_map_onto_the_seam() {
    let receiver = FixtureReceiver::start(vec![
        Scripted::Stop {
            code: "deployment.held".to_string(),
        },
        Scripted::Acknowledge {
            run_id: Some("proposal-7".to_string()),
        },
    ])
    .await;
    let destination = FixtureDestination::new(&receiver.url).expect("a loopback receiver");
    let projected = json!({"id": "a", "answers.age": "045"});
    let stopped = destination
        .deliver(&job_identity(), &deliverable(projected.clone()))
        .await;
    assert_eq!(
        stopped,
        HandOffOutcome::StopPass {
            code: "deployment.held".to_string()
        }
    );
    let acknowledged = destination
        .deliver(&job_identity(), &deliverable(projected))
        .await;
    assert_eq!(
        acknowledged,
        HandOffOutcome::Acknowledged {
            run_id: Some("proposal-7".to_string())
        }
    );
}

/// A stalled receiver stops the pass under the seam's unreachable code,
/// because a delivery with no answer names no destination code of its
/// own.
#[tokio::test]
async fn a_stalled_receiver_stops_under_the_unreachable_code() {
    let receiver = FixtureReceiver::start(vec![Scripted::Hang]).await;
    let destination = FixtureDestination::new(&receiver.url)
        .expect("a loopback receiver")
        .with_timeout(Duration::from_millis(300));
    let outcome = destination
        .deliver(&job_identity(), &deliverable(json!({"id": "a"})))
        .await;
    assert_eq!(
        outcome,
        HandOffOutcome::StopPass {
            code: DESTINATION_UNREACHABLE.to_string()
        }
    );
}

/// A re-delivery of the same item sends identical bytes: the retry
/// identity the destination dedups on is stable across deliveries.
#[tokio::test]
async fn a_redelivery_sends_identical_bytes() {
    let receiver = FixtureReceiver::start(vec![
        Scripted::Acknowledge { run_id: None },
        Scripted::Acknowledge { run_id: None },
    ])
    .await;
    let destination = FixtureDestination::new(&receiver.url).expect("a loopback receiver");
    let item = deliverable(json!({"id": "a", "answers.age": "045"}));
    destination.deliver(&job_identity(), &item).await;
    destination.deliver(&job_identity(), &item).await;
    let requests = receiver.requests();
    assert_eq!(requests.len(), 2, "both deliveries arrived");
    assert_eq!(
        requests[0].body, requests[1].body,
        "the same logical hand-off sends the same bytes"
    );
}

/// No credential crosses the seam: the deliverable carries no
/// authentication header and no credential-shaped member, whatever the
/// source sent.
#[tokio::test]
async fn no_credential_crosses_the_seam() {
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let destination = FixtureDestination::new(&receiver.url).expect("a loopback receiver");
    let projected = json!({"id": "a", "answers.age": "045"});
    destination
        .deliver(&job_identity(), &deliverable(projected))
        .await;
    let delivery = &receiver.requests()[0];
    for (name, value) in &delivery.headers {
        let name = name.to_ascii_lowercase();
        assert!(
            !name.contains("authorization") && !name.contains("cookie") && !name.contains("token"),
            "no credential header crosses the seam: {name}"
        );
        assert!(
            !value.contains("secret:env"),
            "no secret reference crosses the seam: {value}"
        );
    }
    let body: Value = serde_json::from_str(&delivery.body_text()).expect("the body parses");
    let body_text = body.to_string();
    assert!(
        !body_text.contains("credential") && !body_text.contains("password"),
        "no credential member crosses the seam: {body_text}"
    );
}

/// The projection and digest ride the compiled engine path: a page the
/// route produced over the loopback double projects to exactly the
/// declared fields, the digest covers the projection, and the hand-off
/// the fixture destination sends carries that projection and no source
/// payload.
#[tokio::test]
async fn the_projection_rides_the_compiled_engine_path() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let result = run_job_page(&program, None).await.expect("the page runs");
    assert_eq!(result.page.items.len(), 2, "both reply entries are items");
    let receiver = FixtureReceiver::start(vec![
        Scripted::Acknowledge { run_id: None },
        Scripted::Acknowledge {
            run_id: Some("proposal-1".to_string()),
        },
    ])
    .await;
    let destination = FixtureDestination::new(&receiver.url).expect("a loopback receiver");
    let declaration = &program.job.projection;
    let mut digests = Vec::new();
    for item in &result.page.items {
        let projected = projection::project(declaration, &item.value);
        assert_eq!(
            projected,
            json!({"id": item.value["id"], "answers.age": item.value["answers"]["age"]}),
            "the projection carries exactly the declared fields"
        );
        let projected_text = projected.to_string();
        assert!(
            !projected_text.contains("never-projected"),
            "the projection never carries an undeclared source field"
        );
        let digest = projection::item_digest(declaration, &item.value);
        assert!(digest.starts_with("sha256:"), "the digest is plain sha256");
        let deliverable = DeliverableItem {
            key: item.key.clone(),
            sequence: 1,
            digest: digest.clone(),
            prior_run_id: None,
            admitted_before: false,
            projected,
        };
        let outcome = destination.deliver(&program.job.job, &deliverable).await;
        assert!(matches!(outcome, HandOffOutcome::Acknowledged { .. }));
        digests.push(digest);
    }
    // The digest follows the projection: changing a projected field
    // changes it, changing an undeclared one does not.
    let changed_projected =
        serde_json::json!({"id": "a", "answers": {"age": "046", "secret": "x"}});
    let changed = projection::item_digest(declaration, &changed_projected);
    let changed_undeclared =
        serde_json::json!({"id": "a", "answers": {"age": "045", "secret": "x"}});
    assert_ne!(digests[0], changed, "a projected change re-flags the item");
    assert_eq!(
        projection::item_digest(declaration, &changed_undeclared),
        digests[0],
        "an undeclared field never re-flags the item"
    );
    // The two items of the page carry different digests.
    assert_ne!(
        digests[0], digests[1],
        "two different items digest differently"
    );
}

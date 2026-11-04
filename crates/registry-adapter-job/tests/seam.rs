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
use registry_adapter_core::{JobDestination as AuthoredDestination, JobIdentity};
use registry_adapter_engine::job::{compile_job, compile_job_with, run_job_page, JobProgram};
use registry_adapter_job::destination::{
    DeliverableItem, FixtureDestination, HandOffOutcome, JobDestination, DESTINATION_UNREACHABLE,
};
use registry_adapter_job::projection;
use serde_json::{json, Value};
use std::{ffi::OsString, path::PathBuf, sync::Mutex, time::Duration};

static KOBO_ENVIRONMENT: Mutex<()> = Mutex::new(());

struct RestoreEnvironment {
    name: &'static str,
    prior: Option<OsString>,
}

impl Drop for RestoreEnvironment {
    fn drop(&mut self) {
        match &self.prior {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

fn kobotoolbox_program() -> JobProgram {
    let _environment = KOBO_ENVIRONMENT.lock().expect("the environment lock holds");
    let _restore_username = RestoreEnvironment {
        name: "KOBO_USERNAME",
        prior: std::env::var_os("KOBO_USERNAME"),
    };
    let _restore_password = RestoreEnvironment {
        name: "KOBO_PASSWORD",
        prior: std::env::var_os("KOBO_PASSWORD"),
    };
    std::env::set_var("KOBO_USERNAME", "synthetic-kobo-user");
    std::env::set_var("KOBO_PASSWORD", "synthetic-kobo-password");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let example = root.join("products/adapter/examples/kobotoolbox-job");
    compile_job_with(
        &root.join("products/adapter/packs/kobotoolbox/pack.yaml"),
        &example.join("job.yaml"),
        &example.join("job-runtime.example.yaml"),
        &example.join("profile.yaml"),
        &example.join("project.yaml"),
    )
    .expect("the maintained KoboToolbox direct-BReg job compiles")
}

fn map_kobotoolbox(program: &JobProgram, body: Value) -> Result<Value, String> {
    let AuthoredDestination::DirectBreg { mapping, .. } = &program.job.destination else {
        panic!("the maintained KoboToolbox job uses direct BReg")
    };
    program
        .map_destination(
            mapping,
            &json!({"body": body, "headers": {}, "properties": {}}),
        )
        .map_err(|failure| failure.to_string())
}

#[test]
fn kobotoolbox_mapping_accepts_authentic_numeric_strings() {
    let program = kobotoolbox_program();
    let mapped = map_kobotoolbox(
        &program,
        json!({
            "_id": 102,
            "respondent_name": "Fictional Respondent 102",
            "household.household_size": "2"
        }),
    )
    .expect("the authentic Kobo projection maps");

    assert_eq!(
        mapped,
        json!({
            "startInput": {"input": {
                "sourceSubmissionId": "102",
                "respondentName": "Fictional Respondent 102",
                "householdSize": 2
            }},
            "submitBody": {}
        })
    );
}

#[test]
fn kobotoolbox_mapping_preserves_offline_fixture_values() {
    let program = kobotoolbox_program();
    let mapped = map_kobotoolbox(
        &program,
        json!({
            "_id": "opaque-submission-001",
            "respondent_name": "Fictional Respondent 001",
            "household.household_size": 3
        }),
    )
    .expect("the maintained offline fixture shape maps");

    assert_eq!(
        mapped["startInput"]["input"]["sourceSubmissionId"],
        "opaque-submission-001"
    );
    assert_eq!(
        mapped["startInput"]["input"]["respondentName"],
        "Fictional Respondent 001"
    );
    assert_eq!(mapped["startInput"]["input"]["householdSize"], 3);
}

#[test]
fn kobotoolbox_mapping_refuses_invalid_ids_and_household_sizes() {
    let program = kobotoolbox_program();
    for invalid_id in [json!(null), json!(true), json!(2.0), json!([]), json!({})] {
        assert!(
            map_kobotoolbox(
                &program,
                json!({
                    "_id": invalid_id,
                    "respondent_name": "Fictional Respondent",
                    "household.household_size": "2"
                }),
            )
            .is_err(),
            "an invalid submission id must refuse"
        );
    }
    for invalid_size in [
        json!(null),
        json!(true),
        json!(2.0),
        json!("two"),
        json!("2.5"),
        json!("9223372036854775808"),
    ] {
        assert!(
            map_kobotoolbox(
                &program,
                json!({
                    "_id": 102,
                    "respondent_name": "Fictional Respondent",
                    "household.household_size": invalid_size
                }),
            )
            .is_err(),
            "an invalid household size must refuse"
        );
    }
}

/// The generated mapping throws when a required answer is absent, and the
/// runtime reports any mapping failure as a refusal of that item alone.
#[test]
fn kobotoolbox_mapping_refuses_a_projection_missing_the_respondent() {
    let program = kobotoolbox_program();
    for body in [
        json!({"_id": "opaque-submission-003", "household.household_size": 4}),
        json!({
            "_id": "opaque-submission-003",
            "respondent_name": null,
            "household.household_size": 4
        }),
    ] {
        let failure = map_kobotoolbox(&program, body).expect_err("a missing respondent refuses");
        // The runtime reports any script failure as a value-free refusal of the
        // item; the throw text naming the target path stays inside the script.
        assert_eq!(failure, "the script raised an error");
    }
}

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
        first_seen: std::time::SystemTime::UNIX_EPOCH,
        event_time: std::time::SystemTime::UNIX_EPOCH,
        delivery_attempt: 1,
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

/// Stopped, held and acknowledged answers remain distinct at the seam,
/// and item-scoped answers carry their destination reference through.
#[tokio::test]
async fn stop_held_and_acknowledged_answers_map_onto_the_seam() {
    let receiver = FixtureReceiver::start(vec![
        Scripted::Stop {
            code: "deployment.held".to_string(),
        },
        Scripted::Hold {
            code: "idempotency.expired".to_string(),
            run_id: Some("proposal-6".to_string()),
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
    let held = destination
        .deliver(&job_identity(), &deliverable(projected.clone()))
        .await;
    assert_eq!(
        held,
        HandOffOutcome::Held {
            code: "idempotency.expired".to_string(),
            run_id: Some("proposal-6".to_string())
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
            first_seen: std::time::SystemTime::UNIX_EPOCH,
            event_time: std::time::SystemTime::UNIX_EPOCH,
            delivery_attempt: 1,
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

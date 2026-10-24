// SPDX-License-Identifier: Apache-2.0

use super::*;

const INITIAL_DURATION_MINUTES: i64 = 1_500;
const MOVED_DURATION_MINUTES: i64 = 2_880;

async fn lifecycle_fixture() -> Fixture {
    let policy = POLICY
        .replacen("endTime: \"23:30\"", "endTime: \"24:00\"", 1)
        .replacen(
            "durationMinutes: 30\n      bufferBeforeMinutes: 0\n      bufferAfterMinutes: 0",
            "durationMinutes: 30\n      durationSelection: {minimumMinutes: 30, maximumMinutes: 10080, incrementMinutes: 30}\n      allowResourceSelection: true\n      openingCoverage: occupied-interval\n      bufferBeforeMinutes: 15\n      bufferAfterMinutes: 15",
            1,
        );
    let fx = fixture_publishing(
        &policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    begin_current_test_writer(&fx.admin).await;
    fx.admin
        .execute(
            "INSERT INTO scheduling_pool_members(resource_id, pool_id, available) \
             VALUES('station-3','north-counter',true)",
            &[],
        )
        .await
        .expect("a second independently reservable member");
    commit_current_test_writer(&fx.admin).await;
    fx
}

fn selected_availability_uri(
    resource: &str,
    duration_minutes: i64,
    from_minutes: i64,
    to_minutes: i64,
) -> String {
    format!(
        "{}&durationMinutes={duration_minutes}&resource={resource}",
        availability_uri(OFFERING, from_minutes, to_minutes)
    )
}

async fn first_selected_slot(
    fx: &Fixture,
    resource: &str,
    duration_minutes: i64,
    from_minutes: i64,
    to_minutes: i64,
) -> DateTime<Utc> {
    let (status, page) = fx
        .get(
            &selected_availability_uri(resource, duration_minutes, from_minutes, to_minutes),
            &fx.reader,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["kind"] == "slot")
        .map(|entry| moment(entry, "start"))
        .unwrap_or_else(|| {
            panic!(
                "a {duration_minutes}-minute slot for {resource} inside \
                 [{from_minutes}, {to_minutes}] minutes"
            )
        })
}

async fn selected_slot_is_offered(
    fx: &Fixture,
    resource: &str,
    duration_minutes: i64,
    from_minutes: i64,
    to_minutes: i64,
    expected: DateTime<Utc>,
) -> bool {
    let (status, page) = fx
        .get(
            &selected_availability_uri(resource, duration_minutes, from_minutes, to_minutes),
            &fx.reader,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    page["items"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|entry| entry["kind"] == "slot" && moment(entry, "start") == expected)
    })
}

fn selected_admission(
    fx: &Fixture,
    start: DateTime<Utc>,
    duration_minutes: i64,
    resource: &str,
) -> Value {
    let mut request = admission(fx, OFFERING, start);
    request["durationMinutes"] = json!(duration_minutes);
    request["resource"] = json!(resource);
    request
}

#[tokio::test]
async fn a_named_multi_day_hold_keeps_its_choices_through_confirmation_and_reschedule() {
    let fx = lifecycle_fixture().await;
    let initial_from = 300;
    let initial_to = 3_000;
    let initial = first_selected_slot(
        &fx,
        "station-3",
        INITIAL_DURATION_MINUTES,
        initial_from,
        initial_to,
    )
    .await;
    let mut hold_request = selected_admission(&fx, initial, INITIAL_DURATION_MINUTES, "station-3");
    hold_request["externalReferences"] = json!([case_reference("selected-lifecycle")]);

    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "selected-lifecycle-hold",
            hold_request,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    assert_eq!(hold["resource"], "station-3");
    assert_eq!(moment(&hold, "start"), initial);
    assert_eq!(
        moment(&hold, "end") - moment(&hold, "start"),
        TimeDelta::minutes(INITIAL_DURATION_MINUTES)
    );

    let hold_id = hold["holdId"].as_str().expect("a hold identifier");
    let confirmation = json!({"hold": hold_id, "admission": null});
    let confirmation_key = "selected-lifecycle-confirm";
    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            confirmation_key,
            confirmation.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirmed}");
    assert_eq!(confirmed["resource"], "station-3");
    assert_eq!(moment(&confirmed, "start"), initial);
    assert_eq!(
        moment(&confirmed, "end") - moment(&confirmed, "start"),
        TimeDelta::minutes(INITIAL_DURATION_MINUTES)
    );
    assert_eq!(
        confirmed["externalReferences"],
        json!([case_reference("selected-lifecycle")])
    );

    let appointment_id = confirmed["appointmentId"]
        .as_str()
        .expect("an appointment identifier")
        .to_owned();
    let observed_revision = confirmed["revision"].as_u64().expect("a revision");
    let (status, read) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read, confirmed);
    let (status, listed) = fx
        .get(
            &appointments_by_reference_uri("selected-lifecycle", 10, None),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["items"], json!([confirmed.clone()]));

    let moved_from = 4_000;
    let moved_to = 8_000;
    let moved_start = first_selected_slot(
        &fx,
        "station-1",
        MOVED_DURATION_MINUTES,
        moved_from,
        moved_to,
    )
    .await;
    let moved_request = json!({
        "observedRevision": observed_revision,
        "admission": selected_admission(
            &fx,
            moved_start,
            MOVED_DURATION_MINUTES,
            "station-1",
        ),
    });
    let move_key = "selected-lifecycle-move";
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            move_key,
            moved_request.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["resource"], "station-1");
    assert_eq!(moment(&moved, "start"), moved_start);
    assert_eq!(
        moment(&moved, "end") - moment(&moved, "start"),
        TimeDelta::minutes(MOVED_DURATION_MINUTES)
    );
    assert_eq!(
        moved["externalReferences"],
        json!([case_reference("selected-lifecycle")])
    );
    assert!(
        selected_slot_is_offered(
            &fx,
            "station-3",
            INITIAL_DURATION_MINUTES,
            initial_from,
            initial_to,
            initial,
        )
        .await,
        "the move releases the complete original occupied interval"
    );
    assert!(
        !selected_slot_is_offered(
            &fx,
            "station-1",
            MOVED_DURATION_MINUTES,
            moved_from,
            moved_to,
            moved_start,
        )
        .await,
        "the move occupies the complete replacement interval"
    );

    let replay = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            move_key,
            moved_request.clone(),
        )
        .await;
    assert_eq!(replay, (StatusCode::OK, moved.clone()));
    let mut changed_move = moved_request;
    changed_move["admission"]["durationMinutes"] = json!(INITIAL_DURATION_MINUTES);
    let (status, refused) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            move_key,
            changed_move,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "idempotency.key-reused");

    let same_owner = token(json!({
        "sub": "principal-agent",
        "azp": CLIENT,
        "registry_scopes": "scheduling-read",
        "registry_actor_kind": "service",
    }));
    let original_receipt = fx
        .post(
            "/v1/appointments/receipt",
            &same_owner,
            confirmation_key,
            confirmation.clone(),
        )
        .await;
    assert_eq!(
        original_receipt,
        (StatusCode::OK, confirmed),
        "the retained receipt answers the original confirmation, not current state"
    );
    let changed_confirmation = json!({
        "hold": Uuid::new_v4().to_string(),
        "admission": null,
    });
    let (status, unresolved) = fx
        .post(
            "/v1/appointments/receipt",
            &same_owner,
            confirmation_key,
            changed_confirmation,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{unresolved}");
    assert_eq!(unresolved["code"], "receipt.unresolved");

    let (status, current) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    assert_eq!(current, moved);
    let (status, current_list) = fx
        .get(
            &appointments_by_reference_uri("selected-lifecycle", 10, None),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{current_list}");
    assert_eq!(current_list["items"], json!([current]));
}

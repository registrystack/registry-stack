// SPDX-License-Identifier: Apache-2.0

use super::*;

fn attendance_token(subject: &str, actions: &[&str], now: DateTime<Utc>) -> String {
    let mut grant = grant_claims();
    grant["registry_grant_exp"] = json!(now.timestamp() + 600);
    grant["registry_grant_bounds"]["permissions"] = json!([{
        "service": "registry-update",
        "location": "north-counter",
        "actions": actions,
    }]);
    let mut claims = json!({
        "sub": subject,
        "azp": CLIENT,
        "exp": now.timestamp() + 600,
        "registry_scopes": "",
        "registry_actor_kind": "agent",
    });
    claims.as_object_mut().expect("claims object").extend(
        grant
            .as_object()
            .expect("grant claims object")
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    token(claims)
}

#[allow(clippy::too_many_arguments)]
async fn put_attendance(
    fx: &Fixture,
    appointment_id: &str,
    token: &str,
    key: &str,
    observed_appointment_revision: u64,
    observed_revision: u64,
    state: &str,
    observed_at: DateTime<Utc>,
) -> (StatusCode, Value) {
    fx.request(
        "PUT",
        &format!("/v1/appointments/{appointment_id}/attendance"),
        token,
        Some(key),
        Some(json!({
            "observedAppointmentRevision": observed_appointment_revision,
            "observedRevision": observed_revision,
            "state": state,
            "observedAt": stamp(observed_at),
        })),
    )
    .await
}

#[tokio::test]
async fn only_the_exact_task_action_records_and_corrects_an_observation_idempotently() {
    let fx = fixture().await;
    let (appointment_id, appointment_revision) =
        booked(&fx, 300, 440, "attendance-authority-booking").await;
    let observed_at = pinned_now() - TimeDelta::minutes(5);

    for (label, key_label, credential) in [
        ("catalogue reader", "catalogue-reader", fx.reader.clone()),
        ("booking task", "booking-task", fx.agent.clone()),
        (
            "appointment detail task",
            "appointment-detail-task",
            attendance_token("detail-only", &["appointment.read"], pinned_now()),
        ),
        (
            "other attendance location",
            "other-attendance-location",
            agent_token_outside_its_bounds(),
        ),
    ] {
        let (status, refusal) = put_attendance(
            &fx,
            &appointment_id,
            &credential,
            &format!("attendance-refused-{key_label}"),
            appointment_revision,
            0,
            "arrived",
            observed_at,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label}: {refusal}");
        assert_eq!(refusal["code"], "operation.not-authorized", "{label}");
    }

    let recorder = attendance_token("attendance-desk", &["attendance.record"], pinned_now());
    let (status, arrived) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-arrived",
        appointment_revision,
        0,
        "arrived",
        observed_at,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{arrived}");
    assert_eq!(arrived["appointmentId"], appointment_id);
    assert_eq!(arrived["appointmentRevision"], appointment_revision);
    assert_eq!(arrived["revision"], 1);
    assert_eq!(arrived["state"], "arrived");
    assert_eq!(arrived["observedAt"], stamp(observed_at));
    assert!(arrived["recordedAt"].is_string());

    let replay = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-arrived",
        appointment_revision,
        0,
        "arrived",
        observed_at,
    )
    .await;
    assert_eq!(replay, (StatusCode::OK, arrived.clone()));

    let (status, key_reuse) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-arrived",
        appointment_revision,
        1,
        "completed",
        observed_at,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{key_reuse}");
    assert_eq!(key_reuse["code"], "idempotency.key-reused");

    let (status, no_show) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-no-show",
        appointment_revision,
        1,
        "no-show",
        observed_at,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{no_show}");
    assert_eq!(no_show["revision"], 2);
    assert_eq!(no_show["state"], "no-show");

    let (status, corrected) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-corrected",
        appointment_revision,
        2,
        "completed",
        observed_at,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{corrected}");
    assert_eq!(corrected["revision"], 3);
    assert_eq!(corrected["state"], "completed");

    let claim = fx
        .store
        .claim(Uuid::parse_str(&appointment_id).unwrap())
        .await
        .unwrap()
        .expect("appointment remains");
    assert_eq!(claim.revision, appointment_revision as i64);
    assert_eq!(claim.state, registry_scheduling::store::ClaimState::Active);

    let (status, history) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}/history"),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    let attendance = history["items"]
        .as_array()
        .expect("history page")
        .iter()
        .filter(|entry| {
            entry["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("attendance."))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        attendance.len(),
        3,
        "all corrections remain visible: {history}"
    );
    let mut revisions = attendance
        .iter()
        .map(|entry| entry["detail"]["attendanceRevision"].as_u64().unwrap())
        .collect::<Vec<_>>();
    revisions.sort_unstable();
    assert_eq!(revisions, [1, 2, 3]);
}

/// `recordedAt` is the locked recording decision time, not the request-edge
/// time. The same value must reach the immutable row, public receipt, history,
/// and after-event; replay returns that exact receipt without a second event.
#[tokio::test]
async fn recording_time_is_observed_after_the_claim_lock_and_replay_keeps_one_event() {
    let fx = hook_fixture().await;
    let (appointment_id, appointment_revision) =
        booked(&fx, 300, 440, "attendance-recording-time-booking").await;
    let appointment_uuid = Uuid::parse_str(&appointment_id).expect("an appointment UUID");
    let recorder = attendance_token("attendance-clock", &["attendance.record"], pinned_now());
    let observed_at = pinned_now() - TimeDelta::minutes(5);
    let body = json!({
        "observedAppointmentRevision": appointment_revision,
        "observedRevision": 0,
        "state": "arrived",
        "observedAt": stamp(observed_at),
    });
    let http = fx.http.clone();
    let store = fx.store.clone();
    let mut admin = fx.admin;

    let holder = admin
        .transaction()
        .await
        .expect("the stand-in attendance transaction opens");
    holder
        .execute(
            "SELECT claim_id FROM scheduling_claims WHERE claim_id=$1 FOR UPDATE",
            &[&appointment_uuid],
        )
        .await
        .expect("the stand-in holds the appointment claim");
    let holder_pid: i32 = holder
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("the stand-in backend")
        .get(0);

    let write = tokio::spawn(send(
        http.clone(),
        "PUT".to_owned(),
        format!("/v1/appointments/{appointment_id}/attendance"),
        recorder.clone(),
        Some("attendance-recording-time".to_owned()),
        Some(body.clone()),
    ));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let waiting: i64 = holder
            .query_one(
                "SELECT count(DISTINCT pid) FROM pg_locks WHERE $1=ANY(pg_blocking_pids(pid))",
                &[&holder_pid],
            )
            .await
            .expect("read the waiting attendance writer")
            .get(0);
        if waiting > 0 {
            break;
        }
        assert!(
            !write.is_finished(),
            "the attendance write finished before reaching the claim lock"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the attendance write never waited on the claim lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let decided_at = pinned_now() + TimeDelta::minutes(1);
    store.pin_clock(Arc::new(move || decided_at));
    holder
        .commit()
        .await
        .expect("release the appointment claim");

    let (status, observation) = write.await.expect("the attendance task answers");
    assert_eq!(status, StatusCode::OK, "{observation}");
    assert_eq!(moment(&observation, "recordedAt"), decided_at);

    let stored = admin
        .query_one(
            "SELECT o.recorded_at,h.occurred_at,h.detail->>'recordedAt' \
             FROM scheduling_attendance_observations AS o \
             JOIN scheduling_history AS h ON h.claim_id=o.claim_id \
               AND h.kind='attendance.arrived' \
               AND (h.detail->>'attendanceRevision')::bigint=o.revision \
             WHERE o.claim_id=$1 AND o.revision=1",
            &[&appointment_uuid],
        )
        .await
        .expect("read the immutable observation and history");
    assert_eq!(stored.get::<_, DateTime<Utc>>(0), decided_at);
    assert_eq!(stored.get::<_, DateTime<Utc>>(1), decided_at);
    assert_eq!(
        DateTime::parse_from_rfc3339(&stored.get::<_, String>(2))
            .expect("history recordedAt is an instant")
            .with_timezone(&Utc),
        decided_at
    );
    let original_event = admin
        .query_one(
            "SELECT event_id,payload FROM registry_outbox \
             WHERE trigger='appointment.attendance-observed'",
            &[],
        )
        .await
        .expect("read the attendance after-event");
    let original_event_id = original_event.get::<_, Uuid>(0);
    let original_payload = original_event.get::<_, Vec<u8>>(1);
    let envelope = HookEnvelope::from_canonical_bytes(
        &original_payload,
        &EnvelopeLimits::tightened_to(16 * 1024),
    )
    .expect("the stored attendance envelope is canonical");
    assert_eq!(
        moment(&envelope.data, "recordedAt"),
        decided_at,
        "the after-event uses the same locked decision time"
    );

    let later = decided_at + TimeDelta::minutes(1);
    store.pin_clock(Arc::new(move || later));
    let replay = send(
        http,
        "PUT".to_owned(),
        format!("/v1/appointments/{appointment_id}/attendance"),
        recorder,
        Some("attendance-recording-time".to_owned()),
        Some(body),
    )
    .await;
    assert_eq!(replay, (StatusCode::OK, observation));
    let replay_events = admin
        .query(
            "SELECT event_id,payload FROM registry_outbox \
             WHERE trigger='appointment.attendance-observed'",
            &[],
        )
        .await
        .expect("read the replay's event identity");
    assert_eq!(replay_events.len(), 1);
    assert_eq!(replay_events[0].get::<_, Uuid>(0), original_event_id);
    assert_eq!(replay_events[0].get::<_, Vec<u8>>(1), original_payload);
}

#[tokio::test]
async fn concurrent_corrections_accept_exactly_one_observed_revision() {
    let fx = fixture().await;
    let (appointment_id, appointment_revision) =
        booked(&fx, 300, 440, "attendance-race-booking").await;
    let recorder = attendance_token("attendance-race", &["attendance.record"], pinned_now());
    let observed_at = pinned_now() - TimeDelta::minutes(5);
    assert_eq!(
        put_attendance(
            &fx,
            &appointment_id,
            &recorder,
            "attendance-race-first",
            appointment_revision,
            0,
            "arrived",
            observed_at,
        )
        .await
        .0,
        StatusCode::OK
    );

    let first = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-race-completed",
        appointment_revision,
        1,
        "completed",
        observed_at,
    );
    let second = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-race-no-show",
        appointment_revision,
        1,
        "no-show",
        observed_at,
    );
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.0, second.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1,
        "one correction wins: {first:?} {second:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::PRECONDITION_FAILED)
            .count(),
        1,
        "one correction observes a stale revision: {first:?} {second:?}"
    );
    let refusal = if first.0 == StatusCode::PRECONDITION_FAILED {
        first.1
    } else {
        second.1
    };
    assert_eq!(refusal["code"], "revision.mismatch");
}

#[tokio::test]
async fn rescheduling_mints_a_new_visit_and_rejects_the_old_appointment_revision() {
    let fx = fixture().await;
    let (appointment_id, first_appointment_revision) =
        booked(&fx, 300, 440, "attendance-reschedule-booking").await;
    let recorder = attendance_token(
        "attendance-reschedule",
        &["attendance.record"],
        pinned_now(),
    );
    let (status, first_visit) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-before-reschedule",
        first_appointment_revision,
        0,
        "arrived",
        pinned_now() - TimeDelta::minutes(5),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first_visit}");
    assert_eq!(first_visit["revision"], 1);

    let other = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "attendance-reschedule",
            json!({
                "observedRevision": first_appointment_revision,
                "admission": admission(&fx, OFFERING, other),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    let second_appointment_revision = moved["revision"].as_u64().unwrap();

    let (status, detail) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert!(
        detail.get("attendance").is_none(),
        "the moved visit must not revive the previous visit's observation: {detail}"
    );

    let (status, stale) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-stale-visit",
        first_appointment_revision,
        1,
        "no-show",
        pinned_now(),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{stale}");
    assert_eq!(stale["code"], "revision.mismatch");

    let (status, second_visit) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-after-reschedule",
        second_appointment_revision,
        0,
        "arrived",
        pinned_now(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_visit}");
    assert_eq!(
        second_visit["appointmentRevision"],
        second_appointment_revision
    );
    assert_eq!(
        second_visit["revision"], 2,
        "attendance revisions stay globally monotonic while visit CAS restarts at zero"
    );
}

#[tokio::test]
async fn cancelled_and_elapsed_bookings_keep_corrigible_attendance_without_capacity_effects() {
    let fx = fixture().await;
    let (appointment_id, appointment_revision) =
        booked(&fx, 300, 440, "attendance-cancelled-booking").await;
    let initial_recorder = attendance_token(
        "attendance-before-cancel",
        &["attendance.record"],
        pinned_now(),
    );
    let (status, arrived) = put_attendance(
        &fx,
        &appointment_id,
        &initial_recorder,
        "attendance-before-cancel",
        appointment_revision,
        0,
        "arrived",
        pinned_now() - TimeDelta::minutes(5),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{arrived}");
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &fx.agent,
            "attendance-cancel-booking",
            json!({"observedRevision": appointment_revision, "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    let cancelled_revision = cancelled["revision"].as_u64().expect("revision");
    let (status, detail) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(
        detail["attendance"], arrived,
        "cancellation changes capacity state but not the visit binding"
    );

    let later = pinned_now() + TimeDelta::days(2);
    fx.store.pin_clock(Arc::new(move || later));
    let recorder = attendance_token("attendance-late", &["attendance.record"], later);
    let (status, observed) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-cancelled-observation",
        cancelled_revision,
        1,
        "no-show",
        later - TimeDelta::hours(1),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{observed}");
    assert_eq!(observed["appointmentRevision"], cancelled_revision);
    assert_eq!(observed["revision"], 2);
    assert_eq!(observed["state"], "no-show");

    let claim = fx
        .store
        .claim(Uuid::parse_str(&appointment_id).unwrap())
        .await
        .unwrap()
        .expect("cancelled booking remains");
    assert_eq!(claim.revision, cancelled_revision as i64);
    assert_eq!(
        claim.state,
        registry_scheduling::store::ClaimState::Cancelled
    );
}

#[tokio::test]
async fn party_counts_resource_only_bookings_and_window_sessions_each_get_one_stream() {
    use super::multi_window::{room, session, session_admission, session_start, sessions_fixture};

    let mut window = session("attendance-session", 1, session_start(2), 3);
    window.resources = room();
    let fx = sessions_fixture(vec![window.clone()]).await;
    let resource_start = first_slot(&fx, OFFERING, 300, 440).await;
    let mut resource_admission = admission(&fx, OFFERING, resource_start);
    resource_admission
        .as_object_mut()
        .expect("admission object")
        .remove("party");
    let (status, resource_booking) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "attendance-resource-booking",
            json!({"hold": null, "admission": resource_admission}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{resource_booking}");

    let (status, session_booking) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "attendance-session-booking",
            json!({"hold": null, "admission": session_admission(&fx, window.start, 1, None)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{session_booking}");

    let recorder = attendance_token("attendance-shapes", &["attendance.record"], pinned_now());
    for (key, appointment) in [
        ("attendance-resource", &resource_booking),
        ("attendance-session", &session_booking),
    ] {
        let id = appointment["appointmentId"].as_str().unwrap();
        let appointment_revision = appointment["revision"].as_u64().unwrap();
        let (status, observation) = put_attendance(
            &fx,
            id,
            &recorder,
            key,
            appointment_revision,
            0,
            "arrived",
            pinned_now() - TimeDelta::minutes(5),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{observation}");
        assert_eq!(observation["revision"], 1);
        for forbidden in ["attendee", "attendees", "seats", "party", "resource"] {
            assert!(
                observation.get(forbidden).is_none(),
                "{forbidden} was invented: {observation}"
            );
        }
    }

    // The window's parent claim holds the room for every booking in it; it is
    // no appointment, so it carries no attendance.
    let parent: Uuid = fx
        .admin
        .query_one(
            "SELECT claim_id FROM scheduling_claims WHERE kind='window'",
            &[],
        )
        .await
        .expect("read the window parent")
        .get(0);
    let (status, refusal) = put_attendance(
        &fx,
        &parent.to_string(),
        &recorder,
        "attendance-window-parent",
        1,
        0,
        "arrived",
        pinned_now(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["code"], "operation.not-authorized");
}

#[tokio::test]
async fn a_future_effective_time_is_refused_without_a_row_receipt_or_event() {
    let fx = fixture().await;
    let (appointment_id, appointment_revision) =
        booked(&fx, 300, 440, "attendance-future-booking").await;
    let recorder = attendance_token("attendance-future", &["attendance.record"], pinned_now());
    let (status, refusal) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-future",
        appointment_revision,
        0,
        "arrived",
        pinned_now() + TimeDelta::seconds(1),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
    assert_eq!(refusal["code"], "request.unprocessable");

    let counts = fx
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM scheduling_attendance_observations WHERE claim_id=$1), \
                    (SELECT count(*) FROM scheduling_attempts WHERE idempotency_key=$2), \
                    (SELECT count(*) FROM registry_outbox WHERE record_reference=$3)",
            &[
                &Uuid::parse_str(&appointment_id).unwrap(),
                &"attendance-future",
                &format!("/v1/appointments/{appointment_id}"),
            ],
        )
        .await
        .expect("read absence of future observation effects");
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 0);
    assert_eq!(counts.get::<_, i64>(2), 0);
}

#[tokio::test]
async fn attendance_is_off_by_default_and_explicit_in_operational_projection() {
    let fx = fixture().await;
    let (appointment_id, appointment_revision) =
        booked(&fx, 300, 440, "attendance-operational-booking").await;
    let recorder = attendance_token(
        "attendance-operations",
        &["attendance.record"],
        pinned_now(),
    );
    let (status, observation) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-operational",
        appointment_revision,
        0,
        "arrived",
        pinned_now() - TimeDelta::minutes(5),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{observation}");

    let credential = operational_token(
        "attendance-operator",
        "scheduling-read scheduling-appointments-desk scheduling-appointments-supervisor",
    );
    let uri = |profile: &str| {
        format!(
            "/v1/operational/appointments?service=registry-update&location=north-counter&start={}&end={}&timeBasis=displayed&profile={profile}",
            stamp(pinned_now()),
            stamp(pinned_now() + TimeDelta::days(2)),
        )
    };
    let (status, desk) = fx.get(&uri("desk"), &credential).await;
    assert_eq!(status, StatusCode::OK, "{desk}");
    let desk_item = desk["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["appointmentId"] == appointment_id)
        .expect("the appointment is in the operational interval");
    assert!(desk_item.get("attendance").is_none(), "{desk_item}");

    let (status, supervisor) = fx.get(&uri("supervisor"), &credential).await;
    assert_eq!(status, StatusCode::OK, "{supervisor}");
    let supervisor_item = supervisor["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["appointmentId"] == appointment_id)
        .expect("the appointment is in the operational interval");
    assert_eq!(supervisor_item["attendance"], observation);
}

#[tokio::test]
async fn attendance_commit_captures_one_minimized_signed_after_event() {
    let fx = hook_fixture().await;
    let (appointment_id, appointment_revision) =
        booked(&fx, 300, 440, "attendance-hook-booking").await;
    let recorder = attendance_token("attendance-hook", &["attendance.record"], pinned_now());
    let observed_at = pinned_now() - TimeDelta::minutes(5);
    let (status, observation) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-hook",
        appointment_revision,
        0,
        "completed",
        observed_at,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{observation}");

    let first_capture = captured_hook_envelopes(&fx).await;
    let first_event = first_capture
        .iter()
        .find(|(_, trigger, _, _, _, _)| trigger == "appointment.attendance-observed")
        .expect("the first attendance event");
    let first_event_id = first_event.4.id.clone();
    let first_payload = first_event.5.clone();
    let replay = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-hook",
        appointment_revision,
        0,
        "completed",
        observed_at,
    )
    .await;
    assert_eq!(replay, (StatusCode::OK, observation.clone()));
    let after_replay = captured_hook_envelopes(&fx).await;
    let replay_events = after_replay
        .iter()
        .filter(|(_, trigger, _, _, _, _)| trigger == "appointment.attendance-observed")
        .collect::<Vec<_>>();
    assert_eq!(replay_events.len(), 1, "replay captures no second event");
    assert_eq!(replay_events[0].4.id, first_event_id);
    assert_eq!(replay_events[0].5, first_payload);

    let (status, no_show) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-hook-no-show",
        appointment_revision,
        1,
        "no-show",
        observed_at,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{no_show}");
    let (status, corrected) = put_attendance(
        &fx,
        &appointment_id,
        &recorder,
        "attendance-hook-corrected",
        appointment_revision,
        2,
        "arrived",
        observed_at,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{corrected}");

    let captured = captured_hook_envelopes(&fx).await;
    let attendance = captured
        .iter()
        .filter(|(_, trigger, _, _, _, _)| trigger == "appointment.attendance-observed")
        .collect::<Vec<_>>();
    assert_eq!(
        attendance.len(),
        3,
        "one after-event per accepted observation"
    );
    for (index, (event, expected_state)) in attendance
        .into_iter()
        .zip(["completed", "no-show", "arrived"])
        .enumerate()
    {
        let (event_type, _, reference, record_revision, envelope, _) = event;
        assert_eq!(event_type, "attendance-observer");
        assert_eq!(reference, &format!("/v1/appointments/{appointment_id}"));
        assert_eq!(*record_revision, appointment_revision as i64);
        assert_eq!(envelope.data["appointmentId"], appointment_id);
        assert_eq!(envelope.data["appointmentRevision"], appointment_revision);
        assert_eq!(
            envelope.data["attendanceRevision"],
            u64::try_from(index + 1).expect("three revisions fit u64")
        );
        assert_eq!(envelope.data["attendanceState"], expected_state);
        assert_eq!(envelope.data["observedAt"], stamp(observed_at));
        assert!(envelope.data["recordedAt"].is_string());
        for forbidden in ["actor", "grant", "party", "resource", "attendees"] {
            assert!(envelope.data.get(forbidden).is_none(), "{forbidden} leaked");
        }
    }
}

// SPDX-License-Identifier: Apache-2.0

//! An arrival offering that names no window is served by every published
//! window whose `offering` names it. A request picks its window by start, a
//! reschedule may move between the offering's windows, and a window's own
//! physical `resources` are reserved once for the whole window while each
//! booking carries only units.

use super::*;
use registry_scheduling_core::WindowResourceRequirement;

/// The arrival offering that serves every window naming it.
const SESSIONS: &str = "registry-sessions";
pub(super) const FIRST_WINDOW: &str = "sessions-first";
const SECOND_WINDOW: &str = "sessions-second";

/// The test policy plus one arrival offering with no `window`. The
/// exact-time offerings a window reserves its room through accept a request
/// without human counts, as every physical requirement of a parent must.
fn sessions_policy() -> String {
    POLICY
        .replace(
            "      maximumRecipients: 1",
            "      maximumRecipients: 1\n      partyCounts: optional",
        )
        .replace(
            "holdPolicy:",
            &format!(
                "  - id: {SESSIONS}\n\
                 \x20   service: registry-update\n\
                 \x20   label: Registry sessions\n\
                 \x20   mode: arrival-window\n\
                 \x20   location: north-counter\n\
                 \x20   because: test\n\
                 \x20   cancellationCutoffMinutes: 240\n\
                 \x20   arrival:\n\
                 \x20     leadTimeMinutes: 1\n\
                 \x20     horizonDays: 60\n\
                 holdPolicy:"
            ),
        )
}

/// A half-hour session at 09:00 UTC, `days` after the pinned instant, on the
/// test opening's half-hour grid so an exact booking can start with it.
pub(super) fn session_start(days: i64) -> DateTime<Utc> {
    (pinned_now() + TimeDelta::days(days))
        .date_naive()
        .and_hms_opt(9, 0, 0)
        .expect("a morning instant")
        .and_utc()
}

pub(super) fn session(
    id: &str,
    revision: u64,
    start: DateTime<Utc>,
    units: u32,
) -> PublishedWindow {
    PublishedWindow {
        id: id.to_owned(),
        revision,
        offering: SESSIONS.to_owned(),
        location: "north-counter".to_owned(),
        start,
        end: start + TimeDelta::minutes(30),
        units,
        units_policy: RequiredUnitsPolicy::Fixed {
            units: 1,
            because: "test".to_owned(),
        },
        subquotas: vec![WindowSubquota {
            id: format!("{id}-assisted"),
            channel: Channel::Assisted,
            units: 1,
            because: "test".to_owned(),
        }],
        leftover: None,
        staffing: None,
        resources: Vec::new(),
        because: "test".to_owned(),
    }
}

/// The room every booking in a session shares: station-1, reserved once
/// through the exact-time offering that sells it.
pub(super) fn room() -> Vec<WindowResourceRequirement> {
    vec![WindowResourceRequirement {
        requirement: "room".to_owned(),
        offering: OFFERING.to_owned(),
        resource: Some("station-1".to_owned()),
        units: 1,
    }]
}

/// A deployment publishing the sessions `windows` describes.
pub(super) async fn sessions_fixture(windows: Vec<PublishedWindow>) -> Fixture {
    sessions_fixture_with_policy(&sessions_policy(), windows).await
}

/// A deployment of `policy` publishing the sessions `windows` describes.
async fn sessions_fixture_with_policy(policy: &str, windows: Vec<PublishedWindow>) -> Fixture {
    let fx = fixture_publishing(
        policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    let mut facts = records_without(&[]);
    facts.windows = windows;
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("publish the session windows");
    fx
}

/// An admission on the sessions offering at `start`, observing `revision`.
pub(super) fn session_admission(
    fx: &Fixture,
    start: DateTime<Utc>,
    revision: u64,
    channel: Option<&str>,
) -> Value {
    json!({
        "offering": SESSIONS,
        "start": stamp(start),
        "party": {"recipients": 1, "attendees": 1},
        "channel": channel,
        "duplicateKey": null,
        "policyRevision": fx.revision,
        "windowRevision": revision,
        "capabilities": [],
        "prerequisites": [],
    })
}

/// The window entries availability lists for the sessions offering, by
/// window id.
async fn session_entries(fx: &Fixture) -> BTreeMap<String, Value> {
    let (status, page) = fx
        .get(&availability_uri(SESSIONS, 0, 4 * 24 * 60), &fx.reader)
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    page["items"]
        .as_array()
        .expect("availability items")
        .iter()
        .map(|entry| {
            assert_eq!(entry["kind"], "window", "{entry}");
            (
                entry["window"].as_str().expect("a window id").to_owned(),
                entry.clone(),
            )
        })
        .collect()
}

/// Active booked units per window, read from the ledger itself.
async fn booked_units(fx: &Fixture) -> BTreeMap<String, i64> {
    fx.admin
        .query(
            "SELECT supply_id, sum(units)::bigint FROM scheduling_claims \
             WHERE kind='booking' AND state='active' GROUP BY supply_id",
            &[],
        )
        .await
        .expect("read the booked units")
        .iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
        .collect()
}

/// Book one session arrival at `start`, observing `revision`.
async fn book_session(fx: &Fixture, key: &str, start: DateTime<Utc>, revision: u64) -> Value {
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            key,
            json!({"hold": null, "admission": session_admission(fx, start, revision, None)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    appointment
}

#[tokio::test]
async fn a_multi_window_offering_holds_confirms_reschedules_and_cancels_by_start() {
    let first = session(FIRST_WINDOW, 1, session_start(2), 2);
    let second = session(SECOND_WINDOW, 2, session_start(3), 2);
    let fx = sessions_fixture(vec![first.clone(), second.clone()]).await;

    // The catalogue publishes every window the offering serves, in start
    // order, and no single window.
    let (status, catalogue) = fx.get("/v1/offerings", &fx.reader).await;
    assert_eq!(status, StatusCode::OK, "{catalogue}");
    let offering = catalogue["items"]
        .as_array()
        .expect("offerings")
        .iter()
        .find(|offering| offering["id"] == SESSIONS)
        .expect("the sessions offering");
    assert!(offering["window"].is_null(), "{offering}");
    assert_eq!(offering["windows"][0]["id"], FIRST_WINDOW, "{offering}");
    assert_eq!(offering["windows"][0]["revision"], 1);
    assert_eq!(offering["windows"][1]["id"], SECOND_WINDOW, "{offering}");
    assert_eq!(offering["windows"][1]["start"], stamp(second.start));

    let entries = session_entries(&fx).await;
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[FIRST_WINDOW]["start"], stamp(first.start));
    assert_eq!(entries[SECOND_WINDOW]["remaining"], 2);

    // Explain answers each start with the window opening at it, and a start
    // no window opens at with the refusal a booking there receives.
    for (start, public_code) in [
        (first.start, Value::Null),
        (
            first.start + TimeDelta::minutes(30),
            json!("schedule.unpublished"),
        ),
    ] {
        let (status, explained) = fx
            .get(
                &format!(
                    "/v1/availability/explain?offering={SESSIONS}&start={}",
                    stamp(start)
                ),
                &fx.agent,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{explained}");
        assert_eq!(explained["publicCode"], public_code, "{explained}");
    }

    // A start no window opens at is unpublished, as a named window's wrong
    // start always was.
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "sessions-no-window",
            json!({"hold": null, "admission": session_admission(
                &fx,
                first.start + TimeDelta::minutes(30),
                1,
                None,
            )}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
    assert_eq!(refusal["code"], "schedule.unpublished");

    // Hold and confirm on the first window.
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "sessions-hold",
            session_admission(&fx, first.start, 1, None),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let hold_id = hold["holdId"].as_str().expect("a hold identifier");
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "sessions-confirm",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    assert_eq!(appointment["start"], stamp(first.start));
    assert_eq!(appointment["end"], stamp(first.end));
    assert_eq!(
        booked_units(&fx).await,
        BTreeMap::from([(FIRST_WINDOW.to_owned(), 1)])
    );
    let entries = session_entries(&fx).await;
    assert_eq!(entries[FIRST_WINDOW]["remaining"], 1);
    assert_eq!(entries[SECOND_WINDOW]["remaining"], 2);

    // A reschedule to the second window's start moves the booking there,
    // under the second window's revision.
    let appointment_id = appointment["appointmentId"]
        .as_str()
        .expect("an appointment identifier");
    let (status, stale) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "sessions-move-stale",
            json!({
                "observedRevision": appointment["revision"],
                "admission": session_admission(&fx, second.start, 1, None),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{stale}");
    assert_eq!(stale["code"], "revision.mismatch");
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "sessions-move",
            json!({
                "observedRevision": appointment["revision"],
                "admission": session_admission(&fx, second.start, 2, None),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["start"], stamp(second.start));
    assert_eq!(moved["end"], stamp(second.end));
    assert_eq!(
        booked_units(&fx).await,
        BTreeMap::from([(SECOND_WINDOW.to_owned(), 1)])
    );
    let entries = session_entries(&fx).await;
    assert_eq!(entries[FIRST_WINDOW]["remaining"], 2);
    assert_eq!(entries[SECOND_WINDOW]["remaining"], 1);

    // Cancelling frees the second window's unit.
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &fx.agent,
            "sessions-cancel",
            json!({"observedRevision": moved["revision"], "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert!(booked_units(&fx).await.is_empty());
    let entries = session_entries(&fx).await;
    assert_eq!(entries[FIRST_WINDOW]["remaining"], 2);
    assert_eq!(entries[SECOND_WINDOW]["remaining"], 2);
}

/// Two reschedules crossing between the same two windows in opposite
/// directions lock both windows in one order, so neither deadlocks, and the
/// windows' units are never oversold whichever commits first.
#[tokio::test]
async fn crossing_reschedules_between_two_windows_neither_deadlock_nor_overbook() {
    let first = session(FIRST_WINDOW, 1, session_start(2), 1);
    let second = session(SECOND_WINDOW, 2, session_start(3), 2);
    let fx = sessions_fixture(vec![first.clone(), second.clone()]).await;

    let leaving_first = book_session(&fx, "crossing-first", first.start, 1).await;
    let leaving_second = book_session(&fx, "crossing-second", second.start, 2).await;

    let reschedule = |appointment: &Value, key: &'static str, start, revision| {
        let http = fx.http.clone();
        let token = fx.agent.clone();
        let uri = format!(
            "/v1/appointments/{}/reschedule",
            appointment["appointmentId"]
                .as_str()
                .expect("an appointment id")
        );
        let body = json!({
            "observedRevision": appointment["revision"],
            "admission": session_admission(&fx, start, revision, None),
        });
        tokio::spawn(async move {
            send(
                http,
                "POST".into(),
                uri,
                token,
                Some(key.into()),
                Some(body),
            )
            .await
        })
    };
    let (to_second, to_first) = tokio::join!(
        reschedule(&leaving_first, "crossing-to-second", second.start, 2),
        reschedule(&leaving_second, "crossing-to-first", first.start, 1),
    );
    let to_second = to_second.expect("the move to the second window answered");
    let to_first = to_first.expect("the move to the first window answered");
    // The move into the second window always has a unit to take. The move
    // into the first window succeeds only when it commits after the first
    // window's booking left; otherwise it is refused on capacity. Neither is
    // ever a deadlock or an unfinished commitment.
    assert_eq!(to_second.0, StatusCode::OK, "{to_second:?}");
    assert!(
        to_first.0 == StatusCode::OK
            || (to_first.0 == StatusCode::CONFLICT && to_first.1["code"] == "capacity.exhausted"),
        "{to_first:?}"
    );
    let booked = booked_units(&fx).await;
    assert!(
        booked.get(FIRST_WINDOW).copied().unwrap_or(0) <= 1,
        "{booked:?}"
    );
    assert!(
        booked.get(SECOND_WINDOW).copied().unwrap_or(0) <= 2,
        "{booked:?}"
    );
    assert_eq!(booked.values().sum::<i64>(), 2, "{booked:?}");
}

/// A window's resources are one parent claim's allocations: written once when
/// the records publish the window, never again per booking, and conflicting
/// with an exact booking of the same resource over the window's span only.
#[tokio::test]
async fn window_resources_are_reserved_once_and_bookings_carry_only_units() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let second = session(SECOND_WINDOW, 2, session_start(3), 2);
    let fx = sessions_fixture(vec![first.clone(), second.clone()]).await;

    let parents = fx
        .admin
        .query(
            "SELECT c.supply_id, count(a.claim_id) FROM scheduling_claims AS c \
             LEFT JOIN scheduling_claim_allocations AS a ON a.claim_id = c.claim_id \
             WHERE c.kind='window' GROUP BY c.supply_id",
            &[],
        )
        .await
        .expect("read the window parents");
    assert_eq!(
        parents.len(),
        1,
        "only the window with resources has a parent"
    );
    assert_eq!(parents[0].get::<_, String>(0), FIRST_WINDOW);
    assert_eq!(
        parents[0].get::<_, i64>(1),
        1,
        "the room is reserved once for the window"
    );

    for key in ["room-booking-one", "room-booking-two"] {
        let (status, booking) = fx
            .post(
                "/v1/appointments",
                &fx.agent,
                key,
                json!({"hold": null, "admission": session_admission(&fx, first.start, 1, None)}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{booking}");
        let booking_id = Uuid::parse_str(booking["appointmentId"].as_str().expect("an id"))
            .expect("an appointment uuid");
        let allocations: i64 = fx
            .admin
            .query_one(
                "SELECT count(*) FROM scheduling_claim_allocations WHERE claim_id=$1",
                &[&booking_id],
            )
            .await
            .expect("read the booking's allocations")
            .get(0);
        assert_eq!(allocations, 0, "a booking does not reserve the room again");
    }

    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "room-exact-conflict",
            json!({"hold": null, "admission": admission(&fx, OFFERING, first.start)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "capacity.exhausted");

    // The second window reserves nothing, so the station is free then.
    let (status, exact) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "room-exact-elsewhere",
            json!({"hold": null, "admission": admission(&fx, OFFERING, second.start)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{exact}");
}

/// A window whose room an exact booking already holds cannot be published:
/// the parent claim is admitted under the same physical evaluator, and the
/// records replacement is refused rather than double-booking the room.
#[tokio::test]
async fn a_window_cannot_reserve_a_resource_an_exact_booking_holds() {
    let first = session(FIRST_WINDOW, 1, session_start(2), 2);
    let fx = sessions_fixture(vec![first.clone()]).await;
    let (status, exact) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "room-taken-first",
            json!({"hold": null, "admission": admission(&fx, OFFERING, first.start)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{exact}");

    let mut reserving = first.clone();
    reserving.revision = 2;
    reserving.resources = room();
    let mut facts = records_without(&[]);
    facts.windows = vec![reserving];
    let refusal = fx
        .store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect_err("the room is already booked");
    assert!(
        refusal.to_string().contains("window sessions-first"),
        "{refusal}"
    );
    let parents: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='window'",
            &[],
        )
        .await
        .expect("count window parents")
        .get(0);
    assert_eq!(parents, 0, "a refused swap leaves no parent behind");
}

/// An exact booking of the room a window reserves, at `start`.
async fn book_room(fx: &Fixture, key: &str, start: DateTime<Utc>) -> (StatusCode, Value) {
    fx.post(
        "/v1/appointments",
        &fx.agent,
        key,
        json!({"hold": null, "admission": admission(fx, OFFERING, start)}),
    )
    .await
}

/// A window that drops its room requirement, or goes away, releases the room:
/// exact bookings of it over the old span succeed once the records apply.
#[tokio::test]
async fn a_window_that_drops_its_room_or_goes_away_frees_the_room() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let mut second = session(SECOND_WINDOW, 1, session_start(3), 2);
    second.resources = room();
    let fx = sessions_fixture(vec![first.clone(), second.clone()]).await;
    for (key, window) in [("held-first", &first), ("held-second", &second)] {
        let (status, refusal) = book_room(&fx, key, window.start).await;
        assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
        assert_eq!(refusal["code"], "capacity.exhausted");
    }

    // The first window keeps its units but no longer needs the room; the
    // second is withdrawn.
    let mut roomless = first.clone();
    roomless.revision = 2;
    roomless.resources = Vec::new();
    let mut facts = records_without(&[]);
    facts.windows = vec![roomless];
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("an unbooked window drops its room and another goes away");

    let parents: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='window'",
            &[],
        )
        .await
        .expect("count window parents")
        .get(0);
    assert_eq!(parents, 0, "neither window reserves anything now");
    for (key, window) in [("freed-first", &first), ("freed-second", &second)] {
        let (status, exact) = book_room(&fx, key, window.start).await;
        assert_eq!(status, StatusCode::CREATED, "{exact}");
    }
}

/// A window that moves takes its room with it: the old span is free for an
/// exact booking and the new span is held.
#[tokio::test]
async fn a_moved_window_releases_its_old_span_and_holds_the_new_one() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;
    let parent = window_parent(&fx, FIRST_WINDOW).await;

    let mut moved = first.clone();
    moved.revision = 2;
    moved.start = session_start(4);
    moved.end = moved.start + TimeDelta::minutes(30);
    let mut facts = records_without(&[]);
    facts.windows = vec![moved.clone()];
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("an unbooked window moves");

    assert_eq!(window_parent(&fx, FIRST_WINDOW).await, parent);
    let (status, exact) = book_room(&fx, "old-span", first.start).await;
    assert_eq!(status, StatusCode::CREATED, "{exact}");
    let (status, refusal) = book_room(&fx, "new-span", moved.start).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "capacity.exhausted");
}

/// A window admission and a records publication take their locks in one
/// order. The publication takes every supply anchor, the window anchors
/// included, before the revision guard's row; an admission takes its window's
/// anchor before that row. Paused once it holds both, the publication makes
/// the admission wait at the window anchor rather than at the guard, so
/// neither can hold what the other needs, and the admission then answers to
/// the records the publication committed.
#[tokio::test]
async fn window_admission_and_records_publication_follow_one_lock_order() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;
    let body = json!({
        "hold": null,
        "admission": session_admission(&fx, first.start, 1, None),
    });
    let mut facts = records_without(&[]);
    facts.windows = vec![first];
    let (http, agent, store, capture) = (
        fx.http.clone(),
        fx.agent.clone(),
        fx.store.clone(),
        fx.capture.clone(),
    );
    let before = capture.entries().len();
    let admin = fx.admin;
    const PAUSE_LOCK: i64 = 7_341_235_903;
    admin
        .batch_execute(
            "CREATE FUNCTION pause_window_records_publication() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
               PERFORM pg_advisory_xact_lock(7341235903); RETURN NULL; \
             END $$; \
             CREATE TRIGGER pause_window_records_publication \
             BEFORE DELETE ON scheduling_pool_members FOR EACH STATEMENT \
             EXECUTE FUNCTION pause_window_records_publication()",
        )
        .await
        .expect("install the deterministic publication pause");
    admin
        .query_one("SELECT pg_advisory_lock($1)", &[&PAUSE_LOCK])
        .await
        .expect("hold the publication pause");
    let pause_pid: i32 = admin
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("read the pause backend")
        .get(0);

    let publication = tokio::spawn(async move { store.replace_facts(SCHEDULING_ID, &facts).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let blocked: i64 = admin
            .query_one(
                "SELECT count(DISTINCT pid) FROM pg_locks \
                 WHERE $1=ANY(pg_blocking_pids(pid))",
                &[&pause_pid],
            )
            .await
            .expect("read the paused publication")
            .get(0);
        if blocked > 0 {
            break;
        }
        assert!(
            !publication.is_finished(),
            "the publication did not reach its pause"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the publication never reached its pause"
        );
        tokio::task::yield_now().await;
    }

    let admission = tokio::spawn(send(
        http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        agent.clone(),
        Some("window-lock-order".to_owned()),
        Some(body.clone()),
    ));
    // Under the unsafe order the admission would hold the window anchor and
    // wait at the guard's row instead, and the publication would then wait
    // for that anchor.
    loop {
        admin
            .batch_execute("SELECT pg_stat_clear_snapshot()")
            .await
            .expect("refresh the activity snapshot");
        let anchor_blocked: i64 = admin
            .query_one(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE wait_event_type='Lock' \
                   AND query LIKE '%FROM scheduling_supply WHERE supply_id = ANY%FOR UPDATE%'",
                &[],
            )
            .await
            .expect("read the admission anchor wait")
            .get(0);
        if anchor_blocked > 0 {
            break;
        }
        assert!(
            !admission.is_finished(),
            "the admission finished while the publication held its window anchor"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the admission never waited at its window anchor"
        );
        tokio::task::yield_now().await;
    }
    let unlocked: bool = admin
        .query_one("SELECT pg_advisory_unlock($1)", &[&PAUSE_LOCK])
        .await
        .expect("release the publication pause")
        .get(0);
    assert!(unlocked, "the test releases its publication pause");

    // The admission waited on an anchor the publication replaced, so it
    // finishes unfinished and the caller retries against the new records.
    let (status, response) = admission.await.expect("the admission task answers");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
    let audited = one_request_and_one_response(&capture.entries().split_off(before));
    assert_eq!(audited["outcome"], "unfinished", "{audited}");
    publication
        .await
        .expect("the publication task answers")
        .expect("the unchanged records publication commits without a deadlock");

    let (status, retry) = send(
        http,
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        agent,
        Some("window-lock-order-retry".to_owned()),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{retry}");
}

/// The sessions policy with every exact-time offering requiring human
/// counts, so none of them can back a window's room.
fn counted_sessions_policy() -> String {
    sessions_policy().replace("      partyCounts: optional\n", "")
}

/// Records apply checks a window's room requirement against the deployed
/// policy before it reserves anything: a requirement whose exact-time
/// offering needs human counts contradicts the policy, since no party makes
/// the window's reservation.
#[tokio::test]
async fn records_apply_refuses_a_window_room_requirement_the_policy_cannot_reserve() {
    let fx = sessions_fixture_with_policy(&counted_sessions_policy(), Vec::new()).await;
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let mut facts = records_without(&[]);
    facts.windows = vec![first];
    let refusal = fx
        .store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect_err("a counted offering cannot back a window's room");
    assert!(
        matches!(refusal, StoreError::CombinedInvariant(_)),
        "{refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("/windows/0/resources/0/offering: scheduling.records.mismatched-reference"),
        "{refusal}"
    );
    let parents: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='window'",
            &[],
        )
        .await
        .expect("count window parents")
        .get(0);
    assert_eq!(parents, 0, "a refused swap leaves no parent behind");
}

/// A publication answers for the window records it governs: it may not make
/// the exact-time offering a standing window reserves its room through
/// require human counts, which would leave a reservation the runtime could
/// not make again.
#[tokio::test]
async fn a_policy_publication_refuses_to_strand_a_window_room_requirement() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first]).await;
    let deployed = fx
        .store
        .scheduling_meta()
        .await
        .expect("the deployment metadata before the refusal");

    let counted = read_policy(&counted_sessions_policy()).expect("the counted policy");
    let refusal = fx
        .store
        .apply_policy(
            SCHEDULING_ID,
            &counted.policy_digest(),
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &counted,
        )
        .await
        .expect_err("a standing window's room offering keeps optional counts");
    assert!(
        matches!(refusal, StoreError::CombinedInvariant(_)),
        "{refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("/windows/0/resources/0/offering: scheduling.records.mismatched-reference"),
        "{refusal}"
    );
    assert_eq!(
        fx.store
            .scheduling_meta()
            .await
            .expect("the deployment metadata after the refusal"),
        deployed,
        "a refused publication deploys nothing"
    );
}

/// The combined check lets a publication retire an offering a window record
/// names, but not the exact-time offering a standing window reserves its
/// room through: the window's reservation is an active commitment on it.
#[tokio::test]
async fn a_policy_publication_cannot_retire_a_window_room_offering() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first]).await;
    let deployed = fx
        .store
        .scheduling_meta()
        .await
        .expect("the deployment metadata before the refusal");

    let mut retired = read_policy(&sessions_policy()).expect("the sessions policy");
    retired.offerings.retain(|offering| offering.id != OFFERING);
    let refusal = fx
        .store
        .apply_policy(
            SCHEDULING_ID,
            &retired.policy_digest(),
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &retired,
        )
        .await
        .expect_err("a standing window's room offering stays published");
    assert!(matches!(refusal, StoreError::PolicyInUse(_)), "{refusal}");
    assert!(
        refusal
            .to_string()
            .contains(&format!("offering {OFFERING} has active commitments")),
        "{refusal}"
    );
    assert_eq!(
        fx.store
            .scheduling_meta()
            .await
            .expect("the deployment metadata after the refusal"),
        deployed,
        "a refused publication deploys nothing"
    );
}

/// Each window of a multi-window offering keeps its own channel ceiling: an
/// assisted booking exhausts the first window's assisted subquota without
/// touching the second's.
#[tokio::test]
async fn each_window_keeps_its_own_subquota_ceiling() {
    let first = session(FIRST_WINDOW, 1, session_start(2), 2);
    let second = session(SECOND_WINDOW, 2, session_start(3), 2);
    let fx = sessions_fixture(vec![first.clone(), second.clone()]).await;

    let (status, booked) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "ceiling-first",
            json!({"hold": null, "admission": session_admission(&fx, first.start, 1, Some("assisted"))}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booked}");
    let (status, refused) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "ceiling-first-again",
            json!({"hold": null, "admission": session_admission(&fx, first.start, 1, Some("assisted"))}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "capacity.exhausted");
    let (status, other) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "ceiling-second",
            json!({"hold": null, "admission": session_admission(&fx, second.start, 2, Some("assisted"))}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{other}");
    let (status, public) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "ceiling-first-public",
            json!({"hold": null, "admission": session_admission(&fx, first.start, 1, Some("public"))}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{public}");
}

/// Records validation refuses two windows of one offering opening at the same
/// start, so a request's start always names at most one window.
#[tokio::test]
async fn records_refuse_two_windows_of_one_offering_at_one_start() {
    let first = session(FIRST_WINDOW, 1, session_start(2), 2);
    let fx = sessions_fixture(vec![first.clone()]).await;
    let mut twin = session(SECOND_WINDOW, 2, first.start, 2);
    twin.end = first.end;
    let mut facts = records_without(&[]);
    facts.windows = vec![first, twin];
    let refusal = fx
        .store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect_err("two windows of one offering may not share a start");
    assert!(
        refusal.to_string().contains("/windows/1/start"),
        "{refusal}"
    );
}

/// The window parent's claim identifier, read from the ledger.
async fn window_parent(fx: &Fixture, window: &str) -> Uuid {
    fx.admin
        .query_one(
            "SELECT claim_id FROM scheduling_claims WHERE kind='window' AND supply_id=$1",
            &[&window],
        )
        .await
        .expect("read the window parent")
        .get(0)
}

/// The rows of every allocation a claim holds, in a stable order.
async fn allocation_rows(fx: &Fixture, claim_id: Uuid) -> Vec<Value> {
    fx.admin
        .query(
            "SELECT to_jsonb(a) FROM scheduling_claim_allocations AS a WHERE claim_id=$1 \
             ORDER BY requirement_kind, requirement_index, part_index",
            &[&claim_id],
        )
        .await
        .expect("read the claim's allocations")
        .iter()
        .map(|row| row.get(0))
        .collect()
}

/// A second window cannot take a room another window already holds over an
/// overlapping span, and a room that is not available cannot back a window:
/// each parent is admitted under the physical evaluator, so the records
/// replacement is refused rather than double-booking or using absent stock.
#[tokio::test]
async fn a_window_cannot_take_a_room_another_window_holds_or_an_unavailable_room() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;

    // An hour-long session ending with the first one, reserving the same
    // room through the hour-long exact offering that also sells it.
    let mut overlapping = session(SECOND_WINDOW, 2, first.start - TimeDelta::minutes(30), 2);
    overlapping.end = first.end;
    overlapping.resources = vec![WindowResourceRequirement {
        requirement: "room".to_owned(),
        offering: "registry-update-60".to_owned(),
        resource: Some("station-1".to_owned()),
        units: 1,
    }];
    let mut facts = records_without(&[]);
    facts.windows = vec![first.clone(), overlapping];
    let refusal = fx
        .store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect_err("a second window cannot double-book the room");
    assert!(
        refusal
            .to_string()
            .contains("window sessions-second physical allocation refused"),
        "{refusal}"
    );

    let mut later = session(SECOND_WINDOW, 2, session_start(3), 2);
    later.resources = room();
    let mut facts = records_without(&[]);
    facts
        .pools
        .iter_mut()
        .flat_map(|pool| &mut pool.members)
        .find(|member| member.resource_id == "station-1")
        .expect("the room resource")
        .available = false;
    facts.windows = vec![first, later];
    let refusal = fx
        .store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect_err("an unavailable room cannot back a window");
    assert!(
        refusal
            .to_string()
            .contains("window sessions-second physical allocation refused"),
        "{refusal}"
    );
    let parents: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='window'",
            &[],
        )
        .await
        .expect("count window parents")
        .get(0);
    assert_eq!(parents, 1, "only the first window's parent remains");
}

/// A reschedule into a full window is refused and leaves the booking where it
/// was; once a unit there frees, the same move lands.
#[tokio::test]
async fn a_move_into_a_full_window_is_refused_and_leaves_the_booking_in_place() {
    let first = session(FIRST_WINDOW, 1, session_start(2), 1);
    let second = session(SECOND_WINDOW, 2, session_start(3), 1);
    let fx = sessions_fixture(vec![first.clone(), second.clone()]).await;
    let moving = book_session(&fx, "full-move-first", first.start, 1).await;
    let occupying = book_session(&fx, "full-move-second", second.start, 2).await;
    let moving_id = moving["appointmentId"].as_str().expect("an appointment id");

    let (status, refused) = fx
        .post(
            &format!("/v1/appointments/{moving_id}/reschedule"),
            &fx.agent,
            "full-move-refused",
            json!({
                "observedRevision": moving["revision"],
                "admission": session_admission(&fx, second.start, 2, None),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "capacity.exhausted");
    let (status, unchanged) = fx
        .get(&format!("/v1/appointments/{moving_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK, "{unchanged}");
    assert_eq!(unchanged["start"], stamp(first.start));
    assert_eq!(unchanged["revision"], moving["revision"]);
    assert_eq!(
        booked_units(&fx).await,
        BTreeMap::from([(FIRST_WINDOW.to_owned(), 1), (SECOND_WINDOW.to_owned(), 1)])
    );

    let occupying_id = occupying["appointmentId"]
        .as_str()
        .expect("an appointment id");
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{occupying_id}/cancel"),
            &fx.agent,
            "full-move-free",
            json!({"observedRevision": occupying["revision"], "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{moving_id}/reschedule"),
            &fx.agent,
            "full-move-lands",
            json!({
                "observedRevision": moving["revision"],
                "admission": session_admission(&fx, second.start, 2, None),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["start"], stamp(second.start));
    assert_eq!(
        booked_units(&fx).await,
        BTreeMap::from([(SECOND_WINDOW.to_owned(), 1)])
    );
}

/// A policy publication that changes nothing a window's room depends on keeps
/// the window's parent and the room it holds.
#[tokio::test]
async fn an_unrelated_policy_publication_keeps_a_window_room_reservation() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;
    let parent = window_parent(&fx, FIRST_WINDOW).await;
    let before = allocation_rows(&fx, parent).await;
    assert_eq!(before.len(), 1, "{before:?}");

    publish_relabelled_policy(&fx).await;

    assert_eq!(window_parent(&fx, FIRST_WINDOW).await, parent);
    assert_eq!(allocation_rows(&fx, parent).await, before);
}

/// Publish the sessions policy with only a service label changed, a
/// publication nothing a window's room depends on.
async fn publish_relabelled_policy(fx: &Fixture) {
    let mut policy = read_policy(&sessions_policy()).expect("the sessions policy");
    policy.services[0].label = "Registry update service".to_owned();
    fx.store
        .apply_policy(
            SCHEDULING_ID,
            &policy.policy_digest(),
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &policy,
        )
        .await
        .expect("an unrelated label change keeps the window's room");
}

/// Record `resource` absent over `window`'s span.
fn close_over(facts: &mut SchedulingFacts, resource: &str, window: &PublishedWindow) {
    facts
        .pools
        .iter_mut()
        .flat_map(|pool| &mut pool.members)
        .find(|member| member.resource_id == resource)
        .expect("the closed resource")
        .availability = Some(
        serde_json::from_value(json!({"closures": [{
            "start": stamp(window.start),
            "end": stamp(window.end),
        }]}))
        .expect("a member closure"),
    );
}

/// A policy publication does not re-reserve a window's room. Once the room's
/// absence is recorded over the window, the next records apply keeps the
/// standing reservation, exactly as it does when no publication came between.
#[tokio::test]
async fn a_policy_publication_leaves_a_window_room_to_its_record() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;
    let parent = window_parent(&fx, FIRST_WINDOW).await;
    let before = allocation_rows(&fx, parent).await;

    publish_relabelled_policy(&fx).await;
    let mut facts = records_without(&[]);
    facts.windows = vec![first.clone()];
    close_over(&mut facts, "station-1", &first);
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("an unchanged window keeps its room across a publication");
    assert_eq!(window_parent(&fx, FIRST_WINDOW).await, parent);
    assert_eq!(allocation_rows(&fx, parent).await, before);
}

/// A window whose room requirement names no resource keeps the member it was
/// given across a policy publication: the next records apply does not move it
/// to another member of the pool.
#[tokio::test]
async fn a_policy_publication_does_not_move_a_window_to_another_room() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = vec![WindowResourceRequirement {
        requirement: "room".to_owned(),
        offering: OFFERING.to_owned(),
        resource: None,
        units: 1,
    }];
    // A second room in the pool the requirement draws from, so the window
    // has somewhere else it could be moved.
    let mut facts = records_without(&[]);
    facts
        .pools
        .iter_mut()
        .find(|pool| pool.id == "north-counter")
        .expect("the room pool")
        .members
        .push(PoolMember {
            resource_id: "station-3".to_owned(),
            capabilities: Vec::new(),
            available: true,
            capacity_units: 1,
            availability: None,
        });
    facts.windows = vec![first.clone()];
    let fx = sessions_fixture(Vec::new()).await;
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("publish the window over a two-room pool");
    let parent = window_parent(&fx, FIRST_WINDOW).await;
    let before = allocation_rows(&fx, parent).await;
    assert_eq!(before.len(), 1, "{before:?}");
    let held = before[0]["resource_id"]
        .as_str()
        .expect("the room the window holds")
        .to_owned();

    publish_relabelled_policy(&fx).await;
    close_over(&mut facts, &held, &first);
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("an unchanged window keeps its room across a publication");
    assert_eq!(
        allocation_rows(&fx, parent).await,
        before,
        "the window keeps the room it holds"
    );
}

/// Fresh busy time a calendar source reports for the room blocks a window from
/// reserving it, as it blocks an exact booking.
#[tokio::test]
async fn fresh_source_busy_time_blocks_a_window_room_reservation() {
    use registry_scheduling::source_busy::{authorize_busy_source, BusySourceIdentity};
    use registry_scheduling_core::BusyReconciliationRequest;

    let start = session_start(2);
    let fx = sessions_fixture(Vec::new()).await;
    let profile = BusyImportProfileConfig {
        scope: "scheduling-busy-write".to_owned(),
        source_id: "facilitator-calendar".to_owned(),
        resources: vec!["station-1".to_owned()],
        maximum_past_days: 2,
        maximum_future_days: 60,
        maximum_span_days: 7,
        maximum_freshness_minutes: 120,
        impact_projection: BusyImpactProjection::CountOnly,
    };
    let profiles = BTreeMap::from([("facilitator".to_owned(), profile)]);
    let authority = authorize_busy_source(
        &profiles,
        &["scheduling-busy-write".to_owned()],
        Some("facilitator"),
        BusySourceIdentity::new(
            "https://issuer.example".to_owned(),
            "calendar-importer".to_owned(),
            "calendar-client".to_owned(),
        )
        .expect("a source identity"),
    )
    .expect("an authorized source");
    let busy: BusyReconciliationRequest = serde_json::from_value(json!({
        "expectedRevision": 0,
        "observedAt": stamp(pinned_now()),
        "freshUntil": stamp(pinned_now() + TimeDelta::minutes(60)),
        "coverage": {
            "start": stamp(start - TimeDelta::hours(1)),
            "end": stamp(start + TimeDelta::hours(2)),
            "resources": ["station-1"]
        },
        "status": "fresh",
        "records": [{
            "externalUid": "private-facilitator-event",
            "externalRevision": "sequence:1",
            "resource": "station-1",
            "start": stamp(start),
            "end": stamp(start + TimeDelta::minutes(30))
        }]
    }))
    .expect("a busy reconciliation");
    let store = fx.store.clone().with_busy_source_profiles(&profiles);
    store
        .apply_busy_reconciliation(&authority, &busy)
        .await
        .expect("apply the fresh busy source");

    let mut reserving = session(FIRST_WINDOW, 1, start, 2);
    reserving.resources = room();
    let mut facts = records_without(&[]);
    facts.windows = vec![reserving];
    let refusal = store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect_err("fresh source busy time blocks the room");
    assert!(
        refusal
            .to_string()
            .contains("window sessions-first physical allocation refused"),
        "{refusal}"
    );
}

/// Recording the room's absence over a window keeps the window's standing
/// reservation, and the resource-supply impacts list that reservation once,
/// as a window.
#[tokio::test]
async fn resource_supply_impacts_list_a_window_room_reservation_once() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;
    let parent = window_parent(&fx, FIRST_WINDOW).await;
    let before = allocation_rows(&fx, parent).await;

    let mut facts = records_without(&[]);
    facts.windows = vec![first.clone()];
    facts
        .pools
        .iter_mut()
        .flat_map(|pool| &mut pool.members)
        .find(|member| member.resource_id == "station-1")
        .expect("the room resource")
        .availability = Some(
        serde_json::from_value(json!({"closures": [{
            "start": stamp(first.start),
            "end": stamp(first.end),
        }]}))
        .expect("a member closure"),
    );
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("record the room's absence");
    assert_eq!(
        allocation_rows(&fx, parent).await,
        before,
        "recording an absence keeps the standing reservation"
    );

    let impacts = fx
        .store
        .resource_supply_impacts()
        .await
        .expect("read the resource-supply impacts");
    assert_eq!(impacts.total, 1, "{impacts:?}");
    assert_eq!(impacts.items[0].kind, "window");
    assert_eq!(impacts.items[0].claim_id, parent);
}

/// An occupied worklist lists a booking in a room-reserving window with no
/// allocations of its own, and never lists the window's parent claim.
#[tokio::test]
async fn occupied_worklists_list_window_bookings_but_not_the_window_reservation() {
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;
    let booking = book_session(&fx, "window-worklist", first.start, 1).await;
    let authority =
        super::operational_reads::arrival_operational_authority(first.start, first.end, false);
    let page = fx
        .store
        .list_operational_appointments(&authority, None, 10)
        .await
        .expect("list the occupied worklist");
    assert_eq!(page.len(), 1, "{page:?}");
    assert_eq!(page[0].appointment_id.to_string(), booking["appointmentId"]);
    assert!(page[0]
        .allocations
        .as_ref()
        .expect("allocations are projected")
        .is_empty());
}

/// A window's room is source-owned supply, not a party's commitment: the
/// exact offering's duplicate-key policy does not apply to the parent.
#[tokio::test]
async fn a_window_room_reservation_ignores_the_party_duplicate_key_policy() {
    let policy = sessions_policy().replacen(
        "    cancellationCutoffMinutes: 240",
        "    duplicateActiveKey: subject\n    cancellationCutoffMinutes: 240",
        1,
    );
    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture_with_policy(&policy, vec![first]).await;
    let parent = window_parent(&fx, FIRST_WINDOW).await;
    assert_eq!(allocation_rows(&fx, parent).await.len(), 1);
}

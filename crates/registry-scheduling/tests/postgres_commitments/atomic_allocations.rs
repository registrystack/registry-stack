// SPDX-License-Identifier: Apache-2.0

use super::*;

fn bundle_operator(subject: &str) -> String {
    operational_token(
        subject,
        "scheduling-read scheduling-appointments-desk scheduling-appointments-supervisor",
    )
}

fn bundle_operational_uri(start: DateTime<Utc>, end: DateTime<Utc>) -> String {
    format!(
        "/v1/operational/appointments?service=registry-update&location=north-counter&start={}&end={}&timeBasis=displayed&profile=desk",
        stamp(start),
        stamp(end),
    )
}

fn bundle_policy() -> String {
    POLICY
        .replacen("service: registry-review", "service: registry-update", 1)
        .replacen(
            "holdPolicy: {ttlMinutes: 10, maximumPerCaller: 2, because: test}",
            r#"  - id: registry-chairs-30
    service: registry-update
    label: Chair stock
    mode: exact-time
    location: north-counter
    because: test
    cancellationCutoffMinutes: 240
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 60
      horizonDays: 60
      pool: chairs
      startIncrementMinutes: 30
      maximumRecipients: 1
holdPolicy: {ttlMinutes: 10, maximumPerCaller: 2, because: test}"#,
            1,
        )
}

async fn bundle_fixture() -> Fixture {
    fixture_publishing(
        &bundle_policy(),
        &[
            "chairs".to_owned(),
            "north-counter".to_owned(),
            "two-counter".to_owned(),
        ],
    )
    .await
}

async fn split_bundle_fixture() -> Fixture {
    let fx = bundle_fixture().await;
    let (mut facts, _) = fx.store.facts().await.expect("read bundle supply");
    for pool in &mut facts.pools {
        let second = match pool.id.as_str() {
            "north-counter" => Some("station-3"),
            "two-counter" => Some("station-4"),
            _ => None,
        };
        if let Some(resource_id) = second {
            pool.members[0].capacity_units = 2;
            pool.members.push(PoolMember {
                resource_id: resource_id.to_owned(),
                capabilities: Vec::new(),
                available: true,
                capacity_units: 2,
                availability: None,
            });
        }
    }
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("publish split bundle supply");
    fx
}

fn split_bundle_admission(fx: &Fixture, slot: DateTime<Utc>) -> Value {
    let mut request = admission(fx, OFFERING, slot);
    request["resourceUnits"] = json!(3);
    request["additionalAllocations"] = json!([{
        "offering": SECOND_OFFERING,
        "units": 3
    }]);
    request
}

async fn stored_allocation_parts(
    fx: &Fixture,
    claim_id: &str,
) -> Vec<(String, i16, i16, String, i32)> {
    fx.admin
        .query(
            "SELECT requirement_kind, requirement_index, part_index, resource_id, units \
             FROM scheduling_claim_allocations WHERE claim_id=$1 \
             ORDER BY CASE requirement_kind WHEN 'primary' THEN -1 ELSE requirement_index END, part_index",
            &[&Uuid::parse_str(claim_id).expect("a claim id")],
        )
        .await
        .expect("read allocation parts")
        .into_iter()
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
            )
        })
        .collect()
}

fn bundle_admission(fx: &Fixture, slot: DateTime<Utc>) -> Value {
    let mut request = admission(fx, OFFERING, slot);
    request["additionalAllocations"] = json!([
        {"offering": SECOND_OFFERING},
        {"offering": "registry-chairs-30", "units": 30}
    ]);
    request
}

#[tokio::test]
async fn one_logical_appointment_atomically_books_room_projector_and_thirty_chairs() {
    let fx = bundle_fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let body = json!({"hold": null, "admission": bundle_admission(&fx, slot)});
    let (status, appointment) = fx
        .post("/v1/appointments", &fx.agent, "bundle-create", body.clone())
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    assert_eq!(appointment["allocations"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        appointment["allocations"][0]["requirement"]["kind"],
        "primary"
    );
    assert_eq!(appointment["allocations"][2]["units"], 30);

    let (status, replay) = fx
        .post("/v1/appointments", &fx.agent, "bundle-create", body)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert_eq!(
        replay, appointment,
        "one idempotency receipt names the logical reservation"
    );

    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-capacity",
            json!({"hold": null, "admission": bundle_admission(&fx, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "capacity.exhausted");
    let logical: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='booking' AND state='active'",
            &[],
        )
        .await
        .expect("count logical appointments")
        .get(0);
    assert_eq!(
        logical, 1,
        "a failed bundle leaves no partial logical claim"
    );

    let later = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "bundle-hold",
            bundle_admission(&fx, later),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    assert_eq!(hold["allocations"].as_array().map(Vec::len), Some(3));
    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-confirm",
            json!({"hold": hold["holdId"], "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirmed}");
    assert_eq!(confirmed["allocations"], hold["allocations"]);
    let confirmed_id = confirmed["appointmentId"].as_str().unwrap();
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{confirmed_id}/cancel"),
            &fx.agent,
            "bundle-cancel",
            json!({"observedRevision": confirmed["revision"], "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["allocations"], confirmed["allocations"]);
    let retained: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claim_allocations WHERE claim_id=$1",
            &[&Uuid::parse_str(confirmed_id).unwrap()],
        )
        .await
        .expect("read retained cancelled allocations")
        .get(0);
    assert_eq!(
        retained, 3,
        "cancellation closes one logical claim without erasing allocation history"
    );
}

#[tokio::test]
async fn split_primary_and_additional_allocations_survive_every_lifecycle() {
    let fx = split_bundle_fixture().await;
    let direct_slot = first_slot(&fx, OFFERING, 300, 440).await;
    let direct_body = json!({
        "hold": null,
        "admission": split_bundle_admission(&fx, direct_slot),
    });
    let (status, direct) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "split-direct",
            direct_body.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{direct}");
    assert_eq!(direct["allocations"].as_array().map(Vec::len), Some(4));
    let direct_id = direct["appointmentId"].as_str().expect("appointment id");
    assert_eq!(
        stored_allocation_parts(&fx, direct_id).await,
        vec![
            ("primary".to_owned(), 0, 0, "station-1".to_owned(), 2),
            ("primary".to_owned(), 0, 1, "station-3".to_owned(), 1),
            ("additional".to_owned(), 0, 0, "station-2".to_owned(), 2),
            ("additional".to_owned(), 0, 1, "station-4".to_owned(), 1),
        ]
    );
    let (status, direct_replay) = fx
        .post("/v1/appointments", &fx.agent, "split-direct", direct_body)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{direct_replay}");
    assert_eq!(direct_replay, direct);

    let held_slot = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "split-hold",
            split_bundle_admission(&fx, held_slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    assert_eq!(hold["allocations"].as_array().map(Vec::len), Some(4));
    let hold_id = hold["holdId"].as_str().expect("hold id");
    let held_parts = stored_allocation_parts(&fx, hold_id).await;
    assert_eq!(held_parts[0].2, 0);
    assert_eq!(held_parts[1].2, 1);
    assert_eq!(held_parts[2].2, 0);
    assert_eq!(held_parts[3].2, 1);

    let confirm_body = json!({"hold": hold_id, "admission": null});
    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "split-confirm",
            confirm_body.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirmed}");
    assert_eq!(confirmed["allocations"], hold["allocations"]);
    let confirmed_id = confirmed["appointmentId"]
        .as_str()
        .expect("confirmed appointment id");
    assert_eq!(stored_allocation_parts(&fx, confirmed_id).await, held_parts);
    let (status, confirm_replay) = fx
        .post("/v1/appointments", &fx.agent, "split-confirm", confirm_body)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirm_replay}");
    assert_eq!(confirm_replay, confirmed);

    let moved_slot = first_slot(&fx, OFFERING, 660, 800).await;
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{confirmed_id}/reschedule"),
            &fx.agent,
            "split-reschedule",
            json!({
                "observedRevision": confirmed["revision"],
                "admission": split_bundle_admission(&fx, moved_slot),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["allocations"].as_array().map(Vec::len), Some(4));
    assert_eq!(stored_allocation_parts(&fx, confirmed_id).await, held_parts);
}

#[tokio::test]
async fn overlapping_bundle_requirements_are_actionably_refused() {
    let fx = bundle_fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let mut request = admission(&fx, OFFERING, slot);
    request["additionalAllocations"] = json!([{"offering": OFFERING}]);
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-overlap",
            json!({"hold": null, "admission": request}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
    assert_eq!(refusal["code"], "request.unprocessable");
}

#[tokio::test]
async fn failed_bundle_reschedule_keeps_every_prior_allocation() {
    let fx = bundle_fixture().await;
    let from = first_slot(&fx, OFFERING, 300, 440).await;
    let target = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-reschedule-create",
            json!({"hold": null, "admission": bundle_admission(&fx, from)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = appointment["appointmentId"].as_str().unwrap();

    let (status, blocker) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-reschedule-blocker",
            json!({"hold": null, "admission": admission(&fx, OFFERING, target)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{blocker}");

    let (status, refusal) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "bundle-reschedule-fail",
            json!({
                "observedRevision": appointment["revision"],
                "admission": bundle_admission(&fx, target),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "capacity.exhausted");

    let (status, standing) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK, "{standing}");
    assert_eq!(moment(&standing, "start"), from);
    assert_eq!(standing["allocations"], appointment["allocations"]);
}

#[tokio::test]
async fn stock_drop_blocks_confirmation_when_live_holds_no_longer_fit() {
    let fx = bundle_fixture().await;
    let (mut facts, _) = fx.store.facts().await.expect("read current stock");
    for pool in &mut facts.pools {
        for member in &mut pool.members {
            member.capacity_units = if member.resource_id == "chair-stock" {
                60
            } else {
                2
            };
        }
    }
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("raise stock for two holds");

    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (first_status, first) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "bundle-stock-first",
            bundle_admission(&fx, slot),
        )
        .await;
    let (second_status, second) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "bundle-stock-second",
            bundle_admission(&fx, slot),
        )
        .await;
    assert_eq!(first_status, StatusCode::CREATED, "{first}");
    assert_eq!(second_status, StatusCode::CREATED, "{second}");

    let (mut reduced, _) = fx.store.facts().await.expect("read raised stock");
    for pool in &mut reduced.pools {
        for member in &mut pool.members {
            member.capacity_units = if member.resource_id == "chair-stock" {
                30
            } else {
                1
            };
        }
    }
    fx.store
        .replace_facts(SCHEDULING_ID, &reduced)
        .await
        .expect("record physical stock loss");

    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-stock-confirm",
            json!({"hold": first["holdId"], "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "capacity.exhausted");
    let active_holds: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='hold' AND state='active'",
            &[],
        )
        .await
        .expect("count preserved holds")
        .get(0);
    assert_eq!(
        active_holds, 2,
        "failed confirmation consumes neither logical hold"
    );
}

#[tokio::test]
async fn a_single_request_and_bundle_contend_for_the_same_physical_capacity() {
    let fx = bundle_fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let single = send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        fx.agent.clone(),
        Some("single-bundle-race-single".to_owned()),
        Some(json!({"hold": null, "admission": admission(&fx, OFFERING, slot)})),
    );
    let bundle = send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        fx.agent.clone(),
        Some("single-bundle-race-bundle".to_owned()),
        Some(json!({"hold": null, "admission": bundle_admission(&fx, slot)})),
    );
    let (single, bundle) = tokio::join!(single, bundle);
    let statuses = [single.0, bundle.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1
    );
    let logical: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='booking' AND state='active'",
            &[],
        )
        .await
        .expect("count the race winner")
        .get(0);
    assert_eq!(
        logical, 1,
        "the lock set admits exactly one logical reservation"
    );
}

#[tokio::test]
async fn read_scoped_preview_reports_only_complete_bundle_capacity() {
    let fx = bundle_fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let preview = json!({
        "offering": OFFERING,
        "start": stamp(slot),
        "party": {"recipients": 1, "attendees": 1},
        "additionalAllocations": [
            {"offering": SECOND_OFFERING},
            {"offering": "registry-chairs-30", "units": 30}
        ]
    });
    let (status, available) = fx
        .request(
            "POST",
            "/v1/availability/preview",
            &fx.reader,
            None,
            Some(preview.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{available}");
    assert_eq!(available["capacityAvailable"], true);
    assert!(available.get("publicCode").is_none());

    let (status, booked) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-preview-book",
            json!({"hold": null, "admission": bundle_admission(&fx, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booked}");
    let (status, unavailable) = fx
        .request(
            "POST",
            "/v1/availability/preview",
            &fx.reader,
            None,
            Some(preview),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{unavailable}");
    assert_eq!(unavailable["capacityAvailable"], false);
    assert_eq!(unavailable["publicCode"], "capacity.exhausted");
    assert!(
        unavailable.get("allocations").is_none(),
        "preview never discloses resources"
    );

    let (status, refusal) = fx
        .request(
            "POST",
            "/v1/availability/preview",
            &fx.reader,
            None,
            Some(json!({
                "offering": OFFERING,
                "start": stamp(slot),
                "manager": "scheduling-manager"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
}

#[tokio::test]
async fn operational_projection_exposes_allocation_spans_and_attenuates_resources() {
    let fx = bundle_fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-operational",
            json!({"hold": null, "admission": bundle_admission(&fx, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let uri = bundle_operational_uri(pinned_now(), pinned_now() + TimeDelta::days(2));
    let (status, page) = fx.get(&uri, &bundle_operator("bundle-operator")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let item = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["appointmentId"] == appointment["appointmentId"])
        .expect("the bundle is in the operational work list");
    let allocations = item["allocations"]
        .as_array()
        .expect("the profile projects allocations");
    assert_eq!(allocations.len(), 3);
    assert_eq!(allocations[0]["requirement"]["kind"], "primary");
    assert_eq!(allocations[0]["resource"], "station-1");
    assert_eq!(allocations[1]["resource"], "station-2");
    assert!(allocations[2].get("resource").is_none());
    assert!(allocations.iter().all(|allocation| {
        allocation.get("occupiedStart").is_some() && allocation.get("occupiedEnd").is_some()
    }));
}

#[tokio::test]
async fn operational_filters_match_a_secondary_resource_and_its_earlier_buffer() {
    let policy = bundle_policy().replace(
        "  - id: registry-review-45\n    service: registry-update\n    label: 45-minute record review\n    mode: exact-time\n    location: north-counter\n    because: test\n    cancellationCutoffMinutes: 240\n    exactTime:\n      durationMinutes: 30\n      bufferBeforeMinutes: 0",
        "  - id: registry-review-45\n    service: registry-update\n    label: 45-minute record review\n    mode: exact-time\n    location: north-counter\n    because: test\n    cancellationCutoffMinutes: 240\n    exactTime:\n      durationMinutes: 30\n      bufferBeforeMinutes: 30",
    );
    let fx = fixture_publishing(
        &policy,
        &[
            "chairs".to_owned(),
            "north-counter".to_owned(),
            "two-counter".to_owned(),
        ],
    )
    .await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-buffer-operational",
            json!({"hold": null, "admission": bundle_admission(&fx, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let uri = format!(
        "/v1/operational/appointments?service=registry-update&location=north-counter&start={}&end={}&timeBasis=occupied&profile=desk&resource=station-2",
        stamp(slot - TimeDelta::minutes(20)),
        stamp(slot - TimeDelta::minutes(10)),
    );
    let (status, page) = fx.get(&uri, &bundle_operator("buffer-operator")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| { item["appointmentId"] == appointment["appointmentId"] }));
}

#[tokio::test]
async fn operational_occupied_filter_does_not_match_an_unselected_allocation() {
    let policy = bundle_policy().replace(
        "  - id: registry-review-45\n    service: registry-update\n    label: 45-minute record review\n    mode: exact-time\n    location: north-counter\n    because: test\n    cancellationCutoffMinutes: 240\n    exactTime:\n      durationMinutes: 30\n      bufferBeforeMinutes: 0",
        "  - id: registry-review-45\n    service: registry-update\n    label: 45-minute record review\n    mode: exact-time\n    location: north-counter\n    because: test\n    cancellationCutoffMinutes: 240\n    exactTime:\n      durationMinutes: 30\n      bufferBeforeMinutes: 30",
    );
    let fx = fixture_publishing(
        &policy,
        &[
            "chairs".to_owned(),
            "north-counter".to_owned(),
            "two-counter".to_owned(),
        ],
    )
    .await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-buffer-operational",
            json!({"hold": null, "admission": bundle_admission(&fx, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let uri = format!(
        "/v1/operational/appointments?service=registry-update&location=north-counter&start={}&end={}&timeBasis=occupied&profile=desk&resource=station-1",
        stamp(slot - TimeDelta::minutes(20)),
        stamp(slot - TimeDelta::minutes(10)),
    );
    let (status, page) = fx.get(&uri, &bundle_operator("buffer-operator")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page["items"].as_array().unwrap().is_empty(), "{page}");
}

#[tokio::test]
async fn operational_occupied_pagination_orders_by_the_selected_resource() {
    let policy = bundle_policy().replace(
        "  - id: registry-review-45\n    service: registry-update\n    label: 45-minute record review\n    mode: exact-time\n    location: north-counter\n    because: test\n    cancellationCutoffMinutes: 240\n    exactTime:\n      durationMinutes: 30\n      bufferBeforeMinutes: 0",
        "  - id: registry-review-45\n    service: registry-update\n    label: 45-minute record review\n    mode: exact-time\n    location: north-counter\n    because: test\n    cancellationCutoffMinutes: 240\n    exactTime:\n      durationMinutes: 30\n      bufferBeforeMinutes: 90",
    );
    let fx = fixture_publishing(
        &policy,
        &[
            "chairs".to_owned(),
            "north-counter".to_owned(),
            "two-counter".to_owned(),
        ],
    )
    .await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-buffer-operational",
            json!({"hold": null, "admission": bundle_admission(&fx, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let (status, earlier) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "earlier-primary-only",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot - TimeDelta::minutes(60))}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{earlier}");
    let uri = format!(
        "/v1/operational/appointments?service=registry-update&location=north-counter&start={}&end={}&timeBasis=occupied&profile=desk&resource=station-1&limit=1",
        stamp(slot - TimeDelta::minutes(120)),
        stamp(slot + TimeDelta::minutes(120)),
    );
    let operator = bundle_operator("ordered-resource-operator");
    let (status, first) = fx.get(&uri, &operator).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["items"][0]["appointmentId"], earlier["appointmentId"]);
    let cursor = first["nextCursor"]
        .as_str()
        .expect("the bundle remains on the next page");
    let (status, second) = fx.get(&format!("{uri}&cursor={cursor}"), &operator).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        second["items"][0]["appointmentId"],
        appointment["appointmentId"]
    );
    assert!(second["nextCursor"].is_null());
}
#[tokio::test]
async fn operational_allocation_projection_is_one_revision_snapshot() {
    let fx = bundle_fixture().await;
    let original_slot = first_slot(&fx, OFFERING, 300, 440).await;
    let moved_slot = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-snapshot-create",
            json!({"hold": null, "admission": bundle_admission(&fx, original_slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = appointment["appointmentId"]
        .as_str()
        .expect("appointment id")
        .to_owned();

    fx.store.pause_next_operational_page_between_queries();
    let read = tokio::spawn(send(
        fx.http.clone(),
        "GET".to_owned(),
        bundle_operational_uri(pinned_now(), pinned_now() + TimeDelta::days(2)),
        bundle_operator("snapshot-operator"),
        None,
        None,
    ));
    tokio::time::timeout(
        Duration::from_secs(5),
        fx.store.wait_for_operational_page_pause(),
    )
    .await
    .expect("the operational read reaches its deterministic pause");
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "bundle-snapshot-reschedule",
            json!({
                "observedRevision": appointment["revision"],
                "admission": bundle_admission(&fx, moved_slot),
            }),
        )
        .await;
    fx.store.release_operational_page_pause();
    assert_eq!(status, StatusCode::OK, "{moved}");
    let (status, page) = read.await.expect("operational read task");
    assert_eq!(status, StatusCode::OK, "{page}");
    let item = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["appointmentId"] == appointment["appointmentId"])
        .expect("the original snapshot contains the appointment");
    assert_eq!(item["revision"], appointment["revision"]);
    assert!(item["allocations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|allocation| { allocation["occupiedStart"] == stamp(original_slot) }));
}

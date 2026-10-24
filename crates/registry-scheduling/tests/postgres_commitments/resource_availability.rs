// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn hold_confirmation_rechecks_location_and_required_resource_capabilities() {
    for close_location in [false, true] {
        let policy = POLICY.replacen(
            "label: 30-minute counter update",
            "label: 30-minute counter update\n    requiresCapabilities: [accessible]",
            1,
        );
        let fx = fixture_publishing(
            &policy,
            &["north-counter".to_owned(), "two-counter".to_owned()],
        )
        .await;
        let (mut facts, _) = fx.store.facts().await.unwrap();
        facts
            .pools
            .iter_mut()
            .flat_map(|pool| &mut pool.members)
            .find(|member| member.resource_id == "station-1")
            .unwrap()
            .capabilities = vec!["accessible".to_owned()];
        fx.store.replace_facts(SCHEDULING_ID, &facts).await.unwrap();
        let start = first_slot(&fx, OFFERING, 300, 700).await;
        let mut request = admission(&fx, OFFERING, start);
        request["capabilities"] = json!(["accessible"]);
        let (status, hold) = fx
            .post("/v1/holds", &fx.agent, "eligible-hold", request)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{hold}");
        if close_location {
            facts.exceptions.push(CalendarExceptionRecord {
                id: "closure-after-hold".to_owned(),
                location: "north-counter".to_owned(),
                kind: ExceptionRecordKind::Closure,
                date: start.date_naive().to_string(),
                start_time: "00:00".to_owned(),
                end_time: "24:00".to_owned(),
                reopens: None,
                authority: None,
            });
        } else {
            facts
                .pools
                .iter_mut()
                .flat_map(|pool| &mut pool.members)
                .find(|member| member.resource_id == "station-1")
                .unwrap()
                .capabilities
                .clear();
        }
        fx.store.replace_facts(SCHEDULING_ID, &facts).await.unwrap();
        let (status, answer) = fx
            .post(
                "/v1/appointments",
                &fx.agent,
                "confirm-changed-supply",
                json!({"hold": hold["holdId"]}),
            )
            .await;
        assert_eq!(
            status,
            if close_location {
                StatusCode::CONFLICT
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            },
            "close_location={close_location}: {answer}"
        );
    }
}

/// Confirmation transfers the reservation a live hold already owns, so the
/// clock moving inside the offering's lead time does not revoke it.
#[tokio::test]
async fn a_live_hold_confirms_inside_lead_time() {
    let fx = fixture().await;
    // The test offering's lead time is 60 minutes and its holds live ten, so
    // the earliest admissible start lies exactly one lead time away.
    let start = first_slot(&fx, OFFERING, 60, 170).await;
    assert_eq!(start, pinned_now() + TimeDelta::minutes(60));
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "lead-time-hold",
            admission(&fx, OFFERING, start),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let hold_id = hold["holdId"].as_str().expect("a hold id").to_owned();

    // Two minutes pass: the start is now inside the lead time, and the hold
    // still has eight minutes to live.
    let confirming_at = pinned_now() + TimeDelta::minutes(2);
    assert!(moment(&hold, "expiresAt") > confirming_at);
    fx.store.pin_clock(Arc::new(move || confirming_at));

    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "lead-time-confirm",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirmed}");
    assert_eq!(moment(&confirmed, "start"), start);
    assert_eq!(confirmed["allocations"], hold["allocations"]);
}

#[tokio::test]
async fn dated_resource_supply_persists_blocks_new_capacity_and_reports_existing_bookings() {
    let fx = selectable_interval_fixture().await;
    let start = first_slot(&fx, OFFERING, 300, 700).await;
    let mut selected = admission(&fx, OFFERING, start);
    selected["durationMinutes"] = json!(90);
    selected["resource"] = json!("station-3");
    let (status, booked) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "before-maintenance",
            json!({"admission": selected}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booked}");

    let (mut facts, revision) = fx.store.facts().await.unwrap();
    let affected = facts
        .pools
        .iter_mut()
        .flat_map(|pool| &mut pool.members)
        .find(|member| member.resource_id == "station-3")
        .unwrap();
    // This closure overlaps cleanup, after the displayed booking has ended.
    affected.availability = Some(serde_json::from_value(json!({
        "closures": [{"start": stamp(start + TimeDelta::minutes(90)), "end": stamp(start + TimeDelta::minutes(120))}]
    })).unwrap());
    fx.store
        .replace_facts(SCHEDULING_ID, &facts)
        .await
        .expect("a real absence remains representable");
    let (loaded, new_revision) = fx.store.facts().await.unwrap();
    assert_eq!(loaded, facts);
    assert!(new_revision > revision);
    let impacts = fx.store.resource_supply_impacts().await.unwrap();
    assert_eq!(impacts.total, 1);
    assert_eq!(
        impacts.items[0].claim_id.to_string(),
        booked["appointmentId"]
    );
    assert_eq!(impacts.items[0].resource, "station-3");
    let (status, current) = fx
        .get(
            &format!(
                "/v1/appointments/{}",
                booked["appointmentId"].as_str().unwrap()
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    assert_eq!(
        current["state"], "confirmed",
        "absence cannot cancel a booking"
    );

    let mut blocked = admission(&fx, OFFERING, start + TimeDelta::minutes(120));
    blocked["resource"] = json!("station-3");
    let (status, refusal) = fx
        .post("/v1/holds", &fx.agent, "cleanup-absence", blocked)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "capacity.exhausted");
    let (status, explanation) = fx
        .get(
            &format!(
                "/v1/availability/explain?offering={OFFERING}&start={}&resource=station-3",
                stamp(start + TimeDelta::minutes(120))
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{explanation}");
    assert_eq!(explanation["publicCode"], "capacity.exhausted");

    let mut returned = admission(&fx, OFFERING, start + TimeDelta::minutes(150));
    returned["resource"] = json!("station-3");
    let (status, hold) = fx
        .post("/v1/holds", &fx.agent, "after-maintenance", returned)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    facts
        .pools
        .iter_mut()
        .flat_map(|pool| &mut pool.members)
        .find(|member| member.resource_id == "station-3")
        .unwrap()
        .availability
        .as_mut()
        .unwrap()
        .closures
        .push(registry_scheduling_core::ResourceInterval {
            start: start + TimeDelta::minutes(150),
            end: start + TimeDelta::minutes(180),
        });
    fx.store.replace_facts(SCHEDULING_ID, &facts).await.unwrap();
    let impacts = fx.store.resource_supply_impacts().await.unwrap();
    assert_eq!(
        impacts.total, 2,
        "bookings and live holds both need remediation"
    );
    let (status, confirmation) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "confirm-absent-resource",
            json!({"hold": hold["holdId"]}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{confirmation}");
    assert_eq!(confirmation["code"], "capacity.exhausted");
    let mut invalid = facts.clone();
    let interval = &mut invalid
        .pools
        .iter_mut()
        .flat_map(|pool| &mut pool.members)
        .find(|member| member.resource_id == "station-3")
        .unwrap()
        .availability
        .as_mut()
        .unwrap()
        .closures[0];
    interval.end = interval.start;
    assert!(
        fx.store
            .replace_facts(SCHEDULING_ID, &invalid)
            .await
            .is_err(),
        "typed internal callers cannot persist invalid resource intervals"
    );
    assert_eq!(fx.store.facts().await.unwrap().0, facts);
}

#[tokio::test]
async fn supply_impacts_cover_secondary_removed_and_reduced_stock_without_cancelling() {
    let policy = POLICY.replacen("service: registry-review", "service: registry-update", 1);
    let fx = fixture_publishing(&policy, &["north-counter".into(), "two-counter".into()]).await;
    let start = first_slot(&fx, OFFERING, 300, 700).await;
    let mut request = admission(&fx, OFFERING, start);
    request["additionalAllocations"] = json!([{"offering": SECOND_OFFERING}]);
    let (status, booking) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "impact-bundle",
            json!({"admission": request}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booking}");
    let (original, _) = fx.store.facts().await.unwrap();
    for change in ["unavailable", "removed", "zero-stock"] {
        let mut facts = original.clone();
        let pool = facts
            .pools
            .iter_mut()
            .find(|p| p.id == "two-counter")
            .unwrap();
        match change {
            "unavailable" => pool.members[0].available = false,
            "removed" => pool.members.clear(),
            "zero-stock" => pool.members[0].capacity_units = 0,
            _ => unreachable!(),
        }
        fx.store.replace_facts(SCHEDULING_ID, &facts).await.unwrap();
        let impacts = fx.store.resource_supply_impacts().await.unwrap();
        assert_eq!(impacts.total, 1, "{change}: {impacts:?}");
        assert_eq!(impacts.items[0].resource, "station-2");
        assert_eq!(
            impacts.items[0].claim_id.to_string(),
            booking["appointmentId"]
        );
    }
    begin_current_test_writer(&fx.admin).await;
    fx.admin.execute(
        "UPDATE scheduling_claim_allocations SET allocation_scope_version=0,operational_service=NULL,operational_location=NULL,operational_mode=NULL,anchor_id=NULL WHERE claim_id=$1 AND resource_id='station-2'",
        &[&Uuid::parse_str(booking["appointmentId"].as_str().unwrap()).unwrap()],
    ).await.unwrap();
    commit_current_test_writer(&fx.admin).await;
    assert_eq!(
        fx.store.resource_supply_impacts().await.unwrap().total,
        1,
        "unknown legacy scope does not erase physical capacity truth"
    );
    let (status, current) = fx
        .get(
            &format!(
                "/v1/appointments/{}",
                booking["appointmentId"].as_str().unwrap()
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["state"], "confirmed");
}

#[tokio::test]
async fn stock_reduction_reports_simultaneous_commitments_but_not_disjoint_intervals() {
    let fx = fixture().await;
    let (mut facts, _) = fx.store.facts().await.unwrap();
    facts
        .pools
        .iter_mut()
        .find(|p| p.id == "north-counter")
        .unwrap()
        .members[0]
        .capacity_units = 2;
    fx.store.replace_facts(SCHEDULING_ID, &facts).await.unwrap();
    let start = first_slot(&fx, OFFERING, 300, 700).await;
    for (key, at) in [
        ("overlap-a", start),
        ("overlap-b", start),
        ("disjoint", start + TimeDelta::minutes(60)),
    ] {
        let (status, result) = fx
            .post(
                "/v1/appointments",
                &fx.agent,
                key,
                json!({"admission": admission(&fx, OFFERING, at)}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{result}");
    }
    facts
        .pools
        .iter_mut()
        .find(|p| p.id == "north-counter")
        .unwrap()
        .members[0]
        .capacity_units = 1;
    fx.store.replace_facts(SCHEDULING_ID, &facts).await.unwrap();
    let impacts = fx.store.resource_supply_impacts().await.unwrap();
    assert_eq!(impacts.total, 2, "{impacts:?}");
    assert!(impacts.items.iter().all(|i| i.occupied_start == start));
}

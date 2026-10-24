// SPDX-License-Identifier: Apache-2.0

//! Claims written before atomic allocations reach the 0105 backfill with no
//! immutable labels, so each backfills as one version-0 allocation row with
//! no anchor. That row still counts for capacity, but the service loads only
//! version-1 rows, so these tests pin what happens to a legacy exact-time
//! commitment before and after its rows are rematerialized.

use super::*;

type AllocationScope = (
    i16,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The scope an `OFFERING` allocation on `station-1` carries once its labels
/// and anchor are recovered.
fn anchored_scope() -> AllocationScope {
    (
        1,
        Some("registry-update".to_owned()),
        Some("north-counter".to_owned()),
        Some("exact-time".to_owned()),
        Some("north-counter".to_owned()),
    )
}

/// Return a claim and its allocation rows to the shape a claim written before
/// the operational-read labels has right after the 0101 and 0105 migrations:
/// a version-0 claim with no labels, and the one version-0 primary allocation
/// row the 0105 backfill writes from the claim's own columns, with no labels
/// and no anchor.
async fn degrade_to_legacy(fx: &Fixture, claim_id: Uuid) {
    begin_current_test_writer(&fx.admin).await;
    let claims = fx
        .admin
        .execute(
            "UPDATE scheduling_claims SET operational_scope_version=0, operational_service=NULL, \
             operational_location=NULL, operational_mode=NULL WHERE claim_id=$1",
            &[&claim_id],
        )
        .await
        .expect("strip the claim's operational labels");
    fx.admin
        .execute(
            "DELETE FROM scheduling_claim_allocations WHERE claim_id=$1",
            &[&claim_id],
        )
        .await
        .expect("drop the claim's scoped allocations");
    let backfilled = fx
        .admin
        .execute(
            "INSERT INTO scheduling_claim_allocations(claim_id, requirement_kind, \
             requirement_index, part_index, allocation_scope_version, offering, resource_id, \
             occupied_start, occupied_end, units) \
             SELECT claim_id, 'primary', 0, 0, 0, offering, supply_id, occupied_start, \
                    occupied_end, units \
             FROM scheduling_claims WHERE claim_id=$1",
            &[&claim_id],
        )
        .await
        .expect("write the backfilled legacy allocation");
    commit_current_test_writer(&fx.admin).await;
    assert_eq!(
        (claims, backfilled),
        (1, 1),
        "one legacy claim backfills as one allocation row"
    );
}

async fn allocation_scopes(fx: &Fixture, claim_id: Uuid) -> Vec<AllocationScope> {
    fx.admin
        .query(
            "SELECT allocation_scope_version, operational_service, operational_location, \
             operational_mode, anchor_id FROM scheduling_claim_allocations WHERE claim_id=$1 \
             ORDER BY CASE requirement_kind WHEN 'primary' THEN -1 ELSE requirement_index END, \
                      part_index",
            &[&claim_id],
        )
        .await
        .expect("read the claim's allocation scopes")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
        .collect()
}

async fn claim_scope_and_state(fx: &Fixture, claim_id: Uuid) -> (i16, String) {
    let row = fx
        .admin
        .query_one(
            "SELECT operational_scope_version, state FROM scheduling_claims WHERE claim_id=$1",
            &[&claim_id],
        )
        .await
        .expect("read the claim");
    (row.get(0), row.get(1))
}

async fn booking_count(fx: &Fixture) -> i64 {
    fx.admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='booking'",
            &[],
        )
        .await
        .expect("count bookings")
        .get(0)
}

async fn legacy_hold(fx: &Fixture, slot: DateTime<Utc>, key: &str) -> Uuid {
    let (status, hold) = fx
        .post("/v1/holds", &fx.agent, key, admission(fx, OFFERING, slot))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let hold_id = Uuid::parse_str(hold["holdId"].as_str().expect("a hold id")).expect("a uuid");
    degrade_to_legacy(fx, hold_id).await;
    assert!(
        !slot_offered(fx, OFFERING, 300, 440, slot).await,
        "a version-0 allocation row still consumes its resource"
    );
    hold_id
}

async fn confirm(fx: &Fixture, hold_id: Uuid, key: &str) -> (StatusCode, Value) {
    fx.post(
        "/v1/appointments",
        &fx.agent,
        key,
        json!({"hold": hold_id.to_string(), "admission": null}),
    )
    .await
}

#[tokio::test]
async fn a_legacy_exact_time_hold_without_scoped_allocations_refuses_confirmation() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let hold_id = legacy_hold(&fx, slot, "legacy-unscoped-hold").await;

    let (status, problem) = confirm(&fx, hold_id, "legacy-unscoped-confirm").await;
    // The capacity invariant comes first: confirming through a path that
    // writes no allocation row would consume the hold's row and free the slot
    // for a second booking.
    assert!(
        !slot_offered(&fx, OFFERING, 300, 440, slot).await,
        "a legacy hold's slot is never offered again by its confirmation ({status}, {problem})"
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");
    assert_eq!(
        claim_scope_and_state(&fx, hold_id).await,
        (0, "active".to_owned()),
        "the refused confirmation leaves the hold standing"
    );
    assert_eq!(booking_count(&fx).await, 0, "no booking was written");

    // The caller's way out stays open: releasing the hold returns its slot.
    let (status, _) = fx.delete(&format!("/v1/holds/{hold_id}"), &fx.agent).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        slot_offered(&fx, OFFERING, 300, 440, slot).await,
        "the released legacy hold returns its slot"
    );
}

#[tokio::test]
async fn migration_relabels_a_legacy_hold_allocation_so_confirmation_keeps_capacity() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let hold_id = legacy_hold(&fx, slot, "legacy-migrated-hold").await;

    // A migration run with nothing pending still rematerializes, the same
    // step an upgrade runs right after the 0105 backfill.
    let applied = fx.store.migrate().await.expect("the migration entry point");
    assert!(applied.is_empty(), "no migration was pending: {applied:?}");
    assert_eq!(claim_scope_and_state(&fx, hold_id).await.0, 1);
    assert_eq!(
        allocation_scopes(&fx, hold_id).await,
        vec![anchored_scope()]
    );

    let (status, appointment) = confirm(&fx, hold_id, "legacy-migrated-confirm").await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = Uuid::parse_str(appointment["appointmentId"].as_str().unwrap()).unwrap();
    assert!(
        !slot_offered(&fx, OFFERING, 300, 440, slot).await,
        "the confirmed booking consumes the slot its hold held"
    );
    assert_eq!(
        allocation_scopes(&fx, appointment_id).await,
        vec![anchored_scope()],
        "the booking carries its own scoped allocation"
    );
    assert_eq!(
        claim_scope_and_state(&fx, hold_id).await,
        (1, "consumed".to_owned())
    );
}

#[tokio::test]
async fn an_unanchored_legacy_allocation_stays_unscoped_until_its_anchor_returns() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let hold_id = legacy_hold(&fx, slot, "legacy-unanchored-hold").await;

    // The resource left every pool: its allocation cannot recover an anchor,
    // though the claim's labels come from the retained policy and do.
    fx.store
        .replace_facts(SCHEDULING_ID, &records_without(&["station-1"]))
        .await
        .expect("record the lost resource");
    let coverage =
        registry_scheduling::operational::rematerialize_operational_scopes(&fx.store, &fx.audit)
            .await
            .expect("the operator rematerialization");
    assert_eq!(coverage.unresolved_bookings, 0);
    assert_eq!(claim_scope_and_state(&fx, hold_id).await.0, 1);
    assert_eq!(
        allocation_scopes(&fx, hold_id).await,
        vec![(0, None, None, None, None)],
        "an allocation whose resource has no anchor stays version 0"
    );
    let (status, problem) = confirm(&fx, hold_id, "legacy-unanchored-confirm").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");
    assert_eq!(
        claim_scope_and_state(&fx, hold_id).await,
        (1, "active".to_owned())
    );

    // Restoring the resource's pool membership and rerunning the operator
    // command recovers the anchor, and the hold then confirms normally.
    fx.store
        .replace_facts(SCHEDULING_ID, &records_without(&[]))
        .await
        .expect("restore the resource");
    registry_scheduling::operational::rematerialize_operational_scopes(&fx.store, &fx.audit)
        .await
        .expect("the repeated operator rematerialization");
    assert_eq!(
        allocation_scopes(&fx, hold_id).await,
        vec![anchored_scope()]
    );
    let (status, appointment) = confirm(&fx, hold_id, "legacy-reanchored-confirm").await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    assert!(!slot_offered(&fx, OFFERING, 300, 440, slot).await);
    let appointment_id = Uuid::parse_str(appointment["appointmentId"].as_str().unwrap()).unwrap();
    assert_eq!(
        allocation_scopes(&fx, appointment_id).await,
        vec![anchored_scope()]
    );
}

#[tokio::test]
async fn a_legacy_exact_time_booking_reschedule_replaces_its_unscoped_allocation() {
    let fx = fixture().await;
    let from = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "legacy-booking",
            json!({"hold": null, "admission": admission(&fx, OFFERING, from)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = Uuid::parse_str(appointment["appointmentId"].as_str().unwrap()).unwrap();
    let observed = appointment["revision"].as_u64().unwrap();
    degrade_to_legacy(&fx, appointment_id).await;
    assert!(
        !slot_offered(&fx, OFFERING, 300, 440, from).await,
        "a version-0 allocation row still consumes its resource"
    );

    // An exact-time reschedule always resolves the bundle path, which
    // replaces every allocation row of the claim, version 0 included, with
    // scoped rows at the new interval.
    let to = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "legacy-reschedule",
            json!({"observedRevision": observed, "admission": admission(&fx, OFFERING, to)}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moment(&moved, "start"), to);
    assert!(
        slot_offered(&fx, OFFERING, 300, 440, from).await,
        "the replaced start is bookable again"
    );
    assert!(
        !slot_offered(&fx, OFFERING, 480, 620, to).await,
        "the new start is committed"
    );
    assert_eq!(
        allocation_scopes(&fx, appointment_id).await,
        vec![anchored_scope()],
        "the unscoped row was replaced, not left behind at the old interval"
    );
}

#[tokio::test]
async fn migration_relabels_a_legacy_arrival_window_allocation_with_its_window_anchor() {
    let start = window_start();
    let fx = fixture_with_window(start).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "legacy-arrival",
            arrival(&fx, start, None),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = Uuid::parse_str(appointment["appointmentId"].as_str().unwrap()).unwrap();
    degrade_to_legacy(&fx, appointment_id).await;
    assert_eq!(
        allocation_scopes(&fx, appointment_id).await,
        vec![(0, None, None, None, None)]
    );

    fx.store.migrate().await.expect("the migration entry point");
    assert_eq!(claim_scope_and_state(&fx, appointment_id).await.0, 1);
    assert_eq!(
        allocation_scopes(&fx, appointment_id).await,
        vec![(
            1,
            Some("registry-update".to_owned()),
            Some("north-counter".to_owned()),
            Some("arrival-window".to_owned()),
            Some(WINDOW_ID.to_owned()),
        )],
        "a window claim's allocation is anchored on the window itself"
    );
}

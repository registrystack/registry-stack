// SPDX-License-Identifier: Apache-2.0

use super::*;

async fn keyed_bundle_fixture() -> Fixture {
    let mut policy = read_policy(POLICY).expect("the bundle duplicate policy");
    for offering in &mut policy.offerings {
        if offering.id == OFFERING || offering.id == SECOND_OFFERING {
            offering.duplicate_active_key = Some("subject".to_owned());
        }
        if offering.id == SECOND_OFFERING {
            offering.service = "registry-update".to_owned();
        }
    }
    fixture_publishing_policy(
        policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await
}

fn keyed_bundle_admission(fx: &Fixture, slot: DateTime<Utc>, key: &str) -> Value {
    let mut request = admission(fx, OFFERING, slot);
    request["duplicateKey"] = json!(key);
    request["additionalAllocations"] = json!([{"offering": SECOND_OFFERING}]);
    request
}

#[tokio::test]
async fn a_bundle_checks_the_duplicate_key_for_its_additional_offering() {
    let fx = keyed_bundle_fixture().await;
    let standing_slot = first_slot(&fx, SECOND_OFFERING, 300, 440).await;
    let mut standing = admission(&fx, SECOND_OFFERING, standing_slot);
    standing["duplicateKey"] = json!("subject:bundle-additional");
    let (status, created) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-additional-duplicate-standing",
            json!({"hold": null, "admission": standing}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let bundle_slot = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-additional-duplicate-refused",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    bundle_slot,
                    "subject:bundle-additional",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");
}

#[tokio::test]
async fn a_bundle_secondary_allocation_is_a_global_duplicate_fact() {
    let fx = keyed_bundle_fixture().await;
    let first_start = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, first) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-first",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    first_start,
                    "subject:bundle-secondary-primary",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    let direct_slot = first_slot(&fx, SECOND_OFFERING, 480, 620).await;
    let mut direct = admission(&fx, SECOND_OFFERING, direct_slot);
    direct["duplicateKey"] = json!("subject:bundle-secondary-primary");
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-primary-refused",
            json!({"hold": null, "admission": direct}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");

    let second_slot = first_slot(&fx, OFFERING, 660, 800).await;
    let (status, second) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-second",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    second_slot,
                    "subject:bundle-secondary-additional",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");

    let later_slot = first_slot(&fx, OFFERING, 840, 980).await;
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-additional-refused",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    later_slot,
                    "subject:bundle-secondary-additional",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");
}

#[tokio::test]
async fn bundle_duplicate_recheck_excludes_the_rescheduled_appointment() {
    let fx = keyed_bundle_fixture().await;
    let from = first_slot(&fx, OFFERING, 300, 440).await;
    let target = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-duplicate-reschedule-create",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    from,
                    "subject:bundle-duplicate-reschedule",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = appointment["appointmentId"]
        .as_str()
        .expect("appointment id");

    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "bundle-duplicate-reschedule-move",
            json!({
                "observedRevision": appointment["revision"],
                "admission": keyed_bundle_admission(
                    &fx,
                    target,
                    "subject:bundle-duplicate-reschedule",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moment(&moved, "start"), target);
}

#[tokio::test]
async fn bundle_confirmation_rechecks_global_duplicates_and_keeps_the_hold() {
    let fx = keyed_bundle_fixture().await;
    let held_slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "bundle-confirm-duplicate-hold",
            keyed_bundle_admission(&fx, held_slot, "subject:bundle-confirm"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");

    let standing_slot = first_slot(&fx, SECOND_OFFERING, 480, 620).await;
    let mut standing = admission(&fx, SECOND_OFFERING, standing_slot);
    standing["duplicateKey"] = json!("subject:bundle-confirm");
    let (status, created) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-confirm-duplicate-standing",
            json!({"hold": null, "admission": standing}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let hold_id = hold["holdId"].as_str().expect("hold id");
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-confirm-duplicate-refused",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");
    let state: String = fx
        .admin
        .query_one(
            "SELECT state FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(hold_id).expect("hold UUID")],
        )
        .await
        .expect("read retained hold")
        .get(0);
    assert_eq!(state, "active");
}

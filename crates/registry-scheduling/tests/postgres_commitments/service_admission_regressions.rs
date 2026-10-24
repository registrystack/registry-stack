// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn physical_preview_skips_admission_only_checks_while_booking_keeps_them() {
    let mut policy = read_policy(POLICY).expect("the scheduling test policy");
    let offering = policy
        .offerings
        .iter_mut()
        .find(|offering| offering.id == OFFERING)
        .expect("the primary exact-time offering");
    offering.duplicate_active_key = Some("subject".to_owned());
    offering.prerequisites = vec!["proof".to_owned()];
    let fx = fixture_publishing_policy(
        policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;

    let (status, preview) = fx
        .request(
            "POST",
            "/v1/availability/preview",
            &fx.reader,
            None,
            Some(json!({
                "offering": OFFERING,
                "start": stamp(slot),
                "party": {"recipients": 1, "attendees": 1}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["capacityAvailable"], true);

    let missing_admission_facts = admission(&fx, OFFERING, slot);
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "preview-regression-missing-prerequisite",
            json!({"hold": null, "admission": missing_admission_facts}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
    assert_eq!(refusal["code"], "prerequisite.missing");

    let mut missing_duplicate_key = admission(&fx, OFFERING, slot);
    missing_duplicate_key["prerequisites"] = json!(["proof"]);
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "preview-regression-missing-duplicate-key",
            json!({"hold": null, "admission": missing_duplicate_key}),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{refusal}");
    assert_eq!(refusal["code"], "precondition.required");

    let mut oversized_party = admission(&fx, OFFERING, slot);
    oversized_party["party"] = json!({"recipients": 2, "attendees": 2});
    oversized_party["prerequisites"] = json!(["proof"]);
    oversized_party["duplicateKey"] = json!("subject:one");
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "preview-regression-party-capacity",
            json!({"hold": null, "admission": oversized_party}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
    assert_eq!(refusal["code"], "party.capacity-inadequate");
}

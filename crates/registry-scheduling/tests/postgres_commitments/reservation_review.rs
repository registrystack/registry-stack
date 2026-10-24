// SPDX-License-Identifier: Apache-2.0

use super::*;

/// A multi-day review commitment keeps the same receipt and capacity claim,
/// then starts owner retention at its fixed expiry rather than at creation.
#[tokio::test]
async fn a_three_day_hold_has_one_fixed_deadline_and_retains_its_owner_from_expiry() {
    let policy = POLICY.replace(
        "holdPolicy: {ttlMinutes: 10, maximumPerCaller: 2, because: test}",
        "holdPolicy: {ttlMinutes: 4320, maximumPerCaller: 2, because: reservation review}",
    );
    let fx = fixture_publishing(
        &policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    let slot = first_slot(&fx, OFFERING, 5_000, 5_200).await;
    let request = admission(&fx, OFFERING, slot);
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "reservation-review-hold",
            request.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let hold_id = Uuid::parse_str(hold["holdId"].as_str().expect("a hold UUID"))
        .expect("Scheduling emits UUID hold identifiers");
    let expires_at = moment(&hold, "expiresAt");
    assert_eq!(expires_at, pinned_now() + TimeDelta::days(3));

    let (status, replayed) = fx
        .post("/v1/holds", &fx.agent, "reservation-review-hold", request)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{replayed}");
    assert_eq!(
        replayed, hold,
        "the original command keeps its one deadline"
    );

    assert_eq!(
        fx.store
            .erase_expired_claim_owners(pinned_now() + TimeDelta::days(7), 7)
            .await
            .unwrap(),
        0,
        "retention must not start at hold creation"
    );
    assert!(fx
        .store
        .claim(hold_id)
        .await
        .unwrap()
        .unwrap()
        .is_owned_by(ISSUER, "principal-agent"));

    assert_eq!(
        fx.store
            .erase_expired_claim_owners(expires_at + TimeDelta::days(7), 7)
            .await
            .unwrap(),
        1,
        "owner retention begins at the fixed hold expiry"
    );
    assert!(!fx
        .store
        .claim(hold_id)
        .await
        .unwrap()
        .unwrap()
        .is_owned_by(ISSUER, "principal-agent"));
}

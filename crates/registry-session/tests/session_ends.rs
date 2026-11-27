// SPDX-License-Identifier: Apache-2.0
//! Every way a sign-in or a session ends without the person finishing it:
//! each revokes the refresh tokens it holds, off the request path, and the
//! service never waits on the issuer to end a session.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use support::{Harness, Options, TestClock, FLOW_COOKIE, SESSION_COOKIE};

fn clocked(clock: &std::sync::Arc<TestClock>) -> Options {
    Options {
        clock: Some(clock.clone()),
        ..Options::default()
    }
}

/// Take a staff sign-in through its first hop only, returning the flow cookie
/// the second hop is waiting under and the issuer location it was sent to.
async fn first_staff_hop(harness: &Harness) -> (String, String) {
    let start = harness.start_sign_in("/staff/").await;
    let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
    let callback = harness.authorize_as(start.location(), "staff-a").await;
    let second = harness.callback(&callback, Some(&flow)).await;
    assert_eq!(second.status, StatusCode::FOUND);
    let flow = second.cookie_pair(FLOW_COOKIE).expect("next flow");
    (flow, second.location().to_owned())
}

#[tokio::test]
async fn a_sign_in_nobody_returns_to_has_its_first_hops_token_revoked_when_it_is_reaped() {
    let clock = TestClock::new();
    let harness = Harness::start_with(clocked(&clock)).await;
    first_staff_hop(&harness).await;
    assert_eq!(harness.issuer.live_families(), 1);

    harness.store.reap();
    assert_eq!(harness.issuer.live_families(), 1, "not over yet");

    clock.advance(Duration::from_secs(601));
    let (sign_ins, sessions) = harness.store.reap();
    assert_eq!((sign_ins, sessions), (1, 0));
    harness.issuer.wait_live_families(0).await;
}

#[tokio::test]
async fn a_sign_in_that_returns_after_it_expired_has_its_token_revoked() {
    let clock = TestClock::new();
    let harness = Harness::start_with(clocked(&clock)).await;
    let (flow, location) = first_staff_hop(&harness).await;
    let callback = harness.authorize_as(&location, "staff-a").await;
    clock.advance(Duration::from_secs(601));
    let late = harness.callback(&callback, Some(&flow)).await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST);
    harness.issuer.wait_live_families(0).await;
}

#[tokio::test]
async fn a_second_sign_in_in_the_same_browser_revokes_the_first_ones_hops() {
    let harness = Harness::start().await;
    let (flow, _) = first_staff_hop(&harness).await;
    assert_eq!(harness.issuer.live_families(), 1);

    let again = harness
        .get("/session/sign-in?return=%2Fstaff%2F", Some(&flow))
        .await;
    assert_eq!(again.status, StatusCode::FOUND);
    harness.issuer.wait_live_families(0).await;
}

#[tokio::test]
async fn a_cancelled_callback_does_not_drop_tokens_the_issuer_issued() {
    let harness = Harness::start().await;
    let start = harness.start_sign_in("/staff/").await;
    let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
    let callback = harness.authorize_as(start.location(), "staff-a").await;
    let second = harness.callback(&callback, Some(&flow)).await;
    let flow = second.cookie_pair(FLOW_COOKIE).expect("next flow");
    let callback = harness.authorize_as(second.location(), "staff-a").await;

    harness.issuer.hold_codes();
    let impatient = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(300))
        .build()
        .expect("client");
    let gave_up = impatient
        .get(&callback)
        .header("cookie", &flow)
        .send()
        .await;
    assert!(gave_up.is_err(), "the request timed out");
    harness.issuer.release_codes();

    harness.issuer.wait_live_families(0).await;
    assert_eq!(harness.store.session_count(), 0);
}

#[tokio::test]
async fn sign_out_answers_at_once_while_the_issuer_stalls_and_revokes_afterwards() {
    let sink = support::AuditSink::default();
    let harness = Harness::start_with(Options {
        audit_sink: Some(sink.clone()),
        ..Options::default()
    })
    .await;
    let staff = harness.sign_in("/staff/", "staff-a").await;
    harness.issuer.hold_revocations();

    let impatient = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let out = impatient
        .post(format!("{}/session/sign-out", harness.public))
        .header("cookie", &staff.cookie)
        .header("origin", &harness.public)
        .send()
        .await
        .expect("sign-out answers without the issuer");
    assert_eq!(out.status(), reqwest::StatusCode::SEE_OTHER);
    let cleared = out
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|value| value.to_str().is_ok_and(|v| v.contains("Max-Age=0")));
    assert!(cleared, "the cookie is cleared");
    assert_eq!(
        harness.get("/session/me", Some(&staff.cookie)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(sink.text().contains("sign-out"));

    harness.issuer.release_revocations();
    harness.issuer.wait_live_families(0).await;
}

#[tokio::test]
async fn sign_out_is_never_rate_limited_per_person() {
    let harness = Harness::start_with(Options {
        extra_document: "rateLimits:\n  perPerson:\n    requestsPerMinute: 1\n    burst: 2\n"
            .to_owned(),
        ..Options::default()
    })
    .await;
    // The sign-in took one of the two.
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    assert_eq!(
        harness
            .get("/session/me", Some(&citizen.cookie))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        harness
            .get("/session/me", Some(&citizen.cookie))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS,
        "the person's own bucket is empty"
    );

    let out = harness
        .sign_out(
            Some(&citizen.cookie),
            &[("origin", harness.public.as_str())],
        )
        .await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert!(out
        .set_cookie(SESSION_COOKIE)
        .expect("cleared")
        .contains("Max-Age=0"));
    assert_eq!(harness.store.session_count(), 0);
    harness.issuer.wait_live_families(0).await;
}

#[tokio::test]
async fn a_session_ended_by_sign_out_during_a_renewal_has_its_rotated_token_revoked() {
    let harness = Harness::start().await;
    harness.issuer.set_access_lifetime(2);
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    assert_eq!(harness.issuer.live_families(), 1);
    // The renewal window opens at half the lifetime.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    harness.issuer.hold_refresh_answers();
    let calls = reqwest::Client::new();
    let check = format!("{}/check/api/registry/records", harness.check);
    let cookie = citizen.cookie.clone();
    let pending = tokio::spawn(async move {
        calls
            .get(check)
            .header("cookie", cookie)
            .send()
            .await
            .map(|response| response.status())
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while harness.issuer.refresh_calls() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the renewal reached the issuer");

    let out = harness
        .sign_out(
            Some(&citizen.cookie),
            &[("origin", harness.public.as_str())],
        )
        .await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    // The issuer ignores the spent token. Only the rotated one, which the
    // renewal finds nobody to keep, ends the family.
    harness.issuer.release_refresh_answers();
    harness.issuer.wait_live_families(0).await;
    let _ = pending.await;
}

#[tokio::test]
async fn refused_return_paths_and_callbacks_do_not_drain_the_global_sign_in_bucket() {
    let harness = Harness::start_with(Options {
        extra_document: "rateLimits:\n  globalSignIn:\n    requestsPerMinute: 1\n    burst: 2\n"
            .to_owned(),
        ..Options::default()
    })
    .await;
    for _ in 0..5 {
        let refused = harness.get("/session/sign-in", None).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        let elsewhere = harness
            .get(
                "/session/sign-in?return=https%3A%2F%2Fevil.example%2F",
                None,
            )
            .await;
        assert_eq!(elsewhere.status, StatusCode::BAD_REQUEST);
    }
    let first = harness.start_sign_in("/apply/").await;
    let second = harness.start_sign_in("/apply/").await;
    assert_eq!(first.status, StatusCode::FOUND);
    assert_eq!(second.status, StatusCode::FOUND);
    assert_eq!(
        harness.start_sign_in("/apply/").await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "two accepted starts spent the burst"
    );

    // Both people already at the issuer still come back.
    for start in [first, second] {
        let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
        let callback = harness.authorize_as(start.location(), "citizen-a").await;
        let done = harness.callback(&callback, Some(&flow)).await;
        assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    }
}

#[tokio::test]
async fn signing_in_through_a_browser_ends_the_session_it_already_holds() {
    let sink = support::AuditSink::default();
    let harness = Harness::start_with(Options {
        audit_sink: Some(sink.clone()),
        ..Options::default()
    })
    .await;
    let first = harness.sign_in("/apply/", "citizen-a").await;
    assert_eq!(harness.issuer.live_families(), 1);

    let start = harness.start_sign_in("/apply/").await;
    let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
    let callback = harness.authorize_as(start.location(), "citizen-b").await;
    let second = harness
        .callback(&callback, Some(&format!("{flow}; {}", first.cookie)))
        .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);

    assert_eq!(
        harness.get("/session/me", Some(&first.cookie)).await.status,
        StatusCode::UNAUTHORIZED
    );
    harness.issuer.wait_live_families(1).await;
    assert!(sink.text().contains("\"action\":\"session-ended\""));
}

#[tokio::test]
async fn sessions_pushed_out_by_a_new_sign_in_are_revoked_and_audited() {
    let sink = support::AuditSink::default();
    let harness = Harness::start_with(Options {
        audit_sink: Some(sink.clone()),
        ..Options::default()
    })
    .await;
    let mut cookies = Vec::new();
    for _ in 0..4 {
        cookies.push(harness.sign_in("/apply/", "citizen-a").await.cookie);
    }
    let issued = harness.issuer.issued_refresh_tokens();
    assert_eq!(issued.len(), 4);

    harness.issuer.wait_live_families(3).await;
    let (client, oldest) = &issued[0];
    assert_eq!(
        harness.issuer.try_refresh(client, oldest).await,
        StatusCode::BAD_REQUEST,
        "the oldest session's token was revoked"
    );
    assert_eq!(
        harness.get("/session/me", Some(&cookies[0])).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sink.text().matches("\"action\":\"session-ended\"").count(),
        2,
        "one ended session, a request and a response record"
    );
}

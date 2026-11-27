// SPDX-License-Identifier: Apache-2.0
//! What the service refuses from the issuer: an ID token that fails any one
//! check, a token response missing what a session needs, and an access token
//! for another audience than the hop asked for. A refusal opens no session and
//! revokes what the issuer issued.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use support::{Fault, Harness, SESSION_COOKIE};

/// The process-wide log buffer. A subscriber installed for the whole process
/// keeps every callsite enabled, so what a test asserts on does not depend on
/// which tests ran beside it. The values a test asserts the logs lack are
/// random per test, so other tests' lines cannot match them.
fn captured_logs() -> String {
    static BUFFER: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<Vec<u8>>>> =
        std::sync::OnceLock::new();
    #[derive(Clone)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = BUFFER.get_or_init(|| {
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Sink(buffer.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
        buffer
    });
    String::from_utf8(buffer.lock().expect("logs").clone()).expect("utf8")
}

#[tokio::test]
async fn every_bad_id_token_and_incomplete_response_is_refused_and_revoked() {
    let harness = Harness::start().await;
    for fault in [
        Fault::WrongNonce,
        Fault::WrongIssuer,
        Fault::WrongAudience,
        Fault::TwoAudiencesWithoutAuthorizedParty,
        Fault::WrongAuthorizedParty,
        Fault::Expired,
        Fault::UnlistedAlgorithm,
        Fault::BadSignature,
        Fault::AccessTokenType,
        Fault::UnknownKey,
        Fault::NoIdToken,
        Fault::NoExpiresIn,
        Fault::WrongAccessAudience,
    ] {
        harness.issuer.set_fault(Some(fault));
        let refused = harness.sign_in_attempt("/apply/", "citizen-a").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{fault:?}");
        assert!(refused.set_cookie(SESSION_COOKIE).is_none(), "{fault:?}");
        assert!(refused.marked(), "{fault:?}");
        assert_eq!(harness.store.session_count(), 0, "{fault:?}");
        harness.issuer.wait_live_families(0).await;
    }
    harness.issuer.set_fault(None);
    harness.sign_in("/apply/", "citizen-a").await;
}

#[tokio::test]
async fn a_refused_id_token_logs_a_fixed_reason_never_the_issuer_it_named() {
    captured_logs();
    let harness = Harness::start().await;
    harness.issuer.set_fault(Some(Fault::WrongIssuer));
    let refused = harness.sign_in_attempt("/apply/", "citizen-a").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    harness.issuer.wait_live_families(0).await;
    let text = captured_logs();
    assert!(text.contains("the ID token was refused"), "{text}");
    assert!(text.contains("the issuer does not match"), "{text}");
    assert!(!text.contains("evil.example"), "{text}");
}

#[tokio::test]
async fn a_hop_whose_access_token_names_another_audience_is_refused_and_every_hop_revoked() {
    let harness = Harness::start().await;
    let start = harness.start_sign_in("/staff/").await;
    let flow = start.cookie_pair(support::FLOW_COOKIE).expect("flow");
    let callback = harness.authorize_as(start.location(), "staff-a").await;
    let second = harness.callback(&callback, Some(&flow)).await;
    assert_eq!(second.status, StatusCode::FOUND);
    assert_eq!(harness.issuer.live_families(), 1);

    harness.issuer.set_fault(Some(Fault::WrongAccessAudience));
    let flow = second.cookie_pair(support::FLOW_COOKIE).expect("next flow");
    let callback = harness.authorize_as(second.location(), "staff-a").await;
    let refused = harness.callback(&callback, Some(&flow)).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.set_cookie(SESSION_COOKIE).is_none());
    harness.issuer.wait_live_families(0).await;
}

#[tokio::test]
async fn a_renewal_that_returns_another_audience_ends_the_session_and_revokes_its_tokens() {
    let harness = Harness::start().await;
    harness.issuer.set_access_lifetime(2);
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    assert_eq!(harness.issuer.live_families(), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    harness.issuer.set_fault(Some(Fault::WrongAccessAudience));
    // The renewal's answer ends the session, whichever call asked for it.
    harness
        .check("GET", "/api/registry/records", Some(&citizen.cookie))
        .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while harness.store.session_count() != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the session ended");
    harness.issuer.wait_live_families(0).await;
    let after = harness
        .check("GET", "/api/registry/records", Some(&citizen.cookie))
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

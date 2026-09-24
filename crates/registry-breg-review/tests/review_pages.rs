// SPDX-License-Identifier: Apache-2.0
//! The review page over loopback HTTP, against an in-process authorization
//! server and a stateful mock registry.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use support::{
    cookie_pair, Harness, Options, ADDRESS_A, B_REQUEST_ID, CITIZEN_A, CITIZEN_B, CURRENT_LINE_A,
    EXPECTED_CSP, FOREIGN_TARGET_REQUEST_ID, HOSTILE_STREET, OTHER_REQUEST_ID, PROPOSED_LOCALITY,
    REQUEST_ID,
};

fn review_path() -> String {
    format!("/requests/{REQUEST_ID}")
}

fn submit_path() -> String {
    format!("/requests/{REQUEST_ID}/submit")
}

fn sign_in_location() -> String {
    format!("/signin?return=%2Frequests%2F{REQUEST_ID}")
}

/// A form post that finds no live session answers a page linking to sign-in,
/// never a redirect: the content security policy's `form-action 'self'`
/// would block a form redirect that continues on to the provider.
fn assert_links_to_sign_in(page: &support::Page) {
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.header("location").is_none(), "{:?}", page.headers);
    assert!(
        page.body.contains("data-outcome=\"sign-in-required\""),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains(&format!("<a href=\"{}\">", sign_in_location())),
        "{}",
        page.body
    );
    assert!(!page.body.contains("<form"), "{}", page.body);
}

#[tokio::test]
async fn t6_submit_without_csrf_is_refused_and_reaches_no_registry() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let view = page.input("view").expect("the review page renders a view");
    let calls = harness.environment.registry.total_calls();

    let refused = harness
        .post(&submit_path(), Some(&cookie), &[("view", &view)])
        .await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.error_code(), Some("csrf-refused"));
    assert_eq!(harness.environment.registry.total_calls(), calls);
    assert_eq!(harness.environment.registry.submits(), 0);
}

#[tokio::test]
async fn t6_submit_with_wrong_csrf_is_refused() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let view = page.input("view").unwrap();
    let csrf = page.input("csrf").unwrap();
    let mut wrong = csrf.clone().into_bytes();
    wrong[0] = if wrong[0] == b'A' { b'B' } else { b'A' };
    let wrong = String::from_utf8(wrong).unwrap();

    for presented in [wrong.as_str(), "", "short"] {
        let refused = harness
            .post(
                &submit_path(),
                Some(&cookie),
                &[("csrf", presented), ("view", &view)],
            )
            .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{presented}");
        assert_eq!(refused.error_code(), Some("csrf-refused"));
    }
    // Another session's token is as wrong as a forged one.
    let (_, other) = harness.review().await;
    let refused = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &other.input("csrf").unwrap()), ("view", &view)],
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(harness.environment.registry.submits(), 0);
}

#[tokio::test]
async fn t6_foreign_or_absolute_return_path_is_refused() {
    let harness = Harness::start().await;
    let upper = REQUEST_ID.to_ascii_uppercase();
    let refused_returns = [
        format!("https%3A%2F%2Fevil.example%2Frequests%2F{REQUEST_ID}"),
        format!("%2F%2Fevil.example%2Frequests%2F{REQUEST_ID}"),
        format!("%2F%5Cevil.example%2Frequests%2F{REQUEST_ID}"),
        format!("%2Frequests%2F{REQUEST_ID}%2F..%2F..%2Fsignout"),
        format!("%2Frequests%2F{REQUEST_ID}%3Fnext%3Dhttps%3A%2F%2Fevil.example"),
        format!("%2Frequests%2F{upper}"),
        "%2Frequests%2Fnot-a-request".to_owned(),
        "%2Fhealth".to_owned(),
        String::new(),
    ];
    for value in &refused_returns {
        let page = harness.get(&format!("/signin?return={value}"), None).await;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(page.error_code(), Some("return-path-refused"), "{value}");
        assert!(page.header("location").is_none());
        assert!(page.set_cookie("breg-review-signin").is_none());
    }
    let missing = harness.get("/signin", None).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    let repeated = harness
        .get(
            &format!("/signin?return=%2Frequests%2F{REQUEST_ID}&return=%2F%2Fevil.example"),
            None,
        )
        .await;
    assert_eq!(repeated.status, StatusCode::BAD_REQUEST);

    let accepted = harness.get(&sign_in_location(), None).await;
    assert_eq!(accepted.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn t6_tampered_or_unknown_session_cookie_is_sent_to_sign_in() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    let calls = harness.environment.registry.total_calls();
    let (name, value) = cookie.split_once('=').unwrap();
    let mut tampered = value.as_bytes().to_vec();
    tampered[5] = if tampered[5] == b'A' { b'B' } else { b'A' };
    let tampered = format!("{name}={}", String::from_utf8(tampered).unwrap());
    let unknown = format!("{name}={}", "A".repeat(43));
    let malformed = format!("{name}=<script>");

    for presented in [&tampered, &unknown, &malformed] {
        let read = harness.get(&review_path(), Some(presented)).await;
        assert_eq!(read.status, StatusCode::SEE_OTHER, "{presented}");
        assert_eq!(read.location(), sign_in_location());
        let submit = harness
            .post(
                &submit_path(),
                Some(presented),
                &[("csrf", &csrf), ("view", &view)],
            )
            .await;
        assert_links_to_sign_in(&submit);
    }
    assert_eq!(harness.environment.registry.total_calls(), calls);
    assert_eq!(harness.environment.registry.submits(), 0);
}

#[tokio::test]
async fn t5_stale_if_match_after_agent_patch_rerenders_and_asks_again() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();

    harness.environment.registry.agent_patch();
    let stale = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;

    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.body);
    assert!(stale.body.contains("data-notice=\"request-changed\""));
    assert_eq!(harness.environment.registry.submit_effects(), 0);
    let fresh_view = stale.input("view").expect("the re-render asks again");
    assert_ne!(fresh_view, view);
    assert_eq!(stale.input("csrf").as_deref(), Some(csrf.as_str()));

    let confirmed = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &fresh_view)],
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.body);
    assert!(confirmed.body.contains("data-outcome=\"submitted\""));
    assert_eq!(harness.environment.registry.submit_effects(), 1);
}

#[tokio::test]
async fn t4_cross_citizen_read_and_submit_give_not_found() {
    let harness = Harness::start().await;
    let (owner_cookie, owner_page) = harness.review().await;
    let owner_view = owner_page.input("view").unwrap();
    let (other_cookie, other_page) = harness.review_as(CITIZEN_B, B_REQUEST_ID).await;
    let other_csrf = other_page.input("csrf").unwrap();

    let foreign = harness.get(&review_path(), Some(&other_cookie)).await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    assert_eq!(foreign.error_code(), Some("not-found"));
    assert!(foreign.input("view").is_none());

    // A record nobody holds reads exactly like a record someone else holds.
    let absent = harness
        .get(
            &format!("/requests/{OTHER_REQUEST_ID}"),
            Some(&owner_cookie),
        )
        .await;
    assert_eq!(absent.status, StatusCode::NOT_FOUND);
    assert_eq!(absent.body, foreign.body);

    // Citizen B cannot borrow citizen A's view, even with B's own CSRF token.
    let submit = harness
        .post(
            &submit_path(),
            Some(&other_cookie),
            &[("csrf", &other_csrf), ("view", &owner_view)],
        )
        .await;
    assert_eq!(submit.status, StatusCode::NOT_FOUND);
    assert_eq!(submit.body, foreign.body);
    assert_eq!(harness.environment.registry.submits(), 0);
    assert!(!harness.environment.registry.submitted(REQUEST_ID));
}

#[tokio::test]
async fn c8_a_draft_naming_another_citizens_address_offers_no_form() {
    let harness = Harness::start().await;
    let (cookie, _) = harness.review_as(CITIZEN_B, B_REQUEST_ID).await;
    let absent = harness
        .get(&format!("/requests/{OTHER_REQUEST_ID}"), Some(&cookie))
        .await;

    let page = harness
        .get(
            &format!("/requests/{FOREIGN_TARGET_REQUEST_ID}"),
            Some(&cookie),
        )
        .await;

    assert_eq!(page.status, StatusCode::NOT_FOUND, "{}", page.body);
    assert_eq!(page.error_code(), Some("not-found"));
    assert_eq!(page.body, absent.body);
    assert!(page.input("view").is_none());
    assert!(!page.body.contains("/submit"));
    assert!(!page.body.contains(CURRENT_LINE_A));
    // The draft itself was readable; the target read under B's own token is
    // what refused.
    let registry = &harness.environment.registry;
    assert_eq!(registry.target_reads(ADDRESS_A), 1);
    assert_eq!(registry.submits(), 0);
}

#[tokio::test]
async fn c8_a_crafted_post_for_a_foreign_target_never_calls_submit() {
    let harness = Harness::start().await;
    let (cookie, own) = harness.review_as(CITIZEN_B, B_REQUEST_ID).await;
    let csrf = own.input("csrf").unwrap();
    let own_view = own.input("view").unwrap();
    let not_found = harness
        .get(&format!("/requests/{OTHER_REQUEST_ID}"), Some(&cookie))
        .await;
    let path = format!("/requests/{FOREIGN_TARGET_REQUEST_ID}/submit");

    for view in [own_view.as_str(), "", "forged-view"] {
        let refused = harness
            .post(&path, Some(&cookie), &[("csrf", &csrf), ("view", view)])
            .await;
        assert_eq!(
            refused.status,
            StatusCode::NOT_FOUND,
            "{view}: {}",
            refused.body
        );
        assert_eq!(refused.body, not_found.body, "{view}");
    }

    let registry = &harness.environment.registry;
    assert_eq!(registry.submits_for(FOREIGN_TARGET_REQUEST_ID), 0);
    assert_eq!(registry.submits(), 0, "{:?}", registry.calls());
    assert!(!registry.submitted(FOREIGN_TARGET_REQUEST_ID));
    assert!(!registry.submitted(B_REQUEST_ID));
}

#[tokio::test]
async fn c8_a_target_that_stops_being_readable_blocks_the_rendered_submit() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();

    harness.environment.registry.withdraw_reader(ADDRESS_A);
    let refused = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;

    assert_eq!(refused.status, StatusCode::NOT_FOUND, "{}", refused.body);
    assert_eq!(refused.error_code(), Some("not-found"));
    assert!(refused.input("view").is_none());
    assert_eq!(harness.environment.registry.submits(), 0);
    assert!(!harness.environment.registry.submitted(REQUEST_ID));
}

#[tokio::test]
async fn review_shows_current_values_beside_proposed_ones() {
    let harness = Harness::start().await;
    let (_, page) = harness.review().await;

    let current = page
        .body
        .find("data-values=\"current\"")
        .expect("current values");
    let proposed = page
        .body
        .find("data-values=\"proposed\"")
        .expect("proposed values");
    assert!(current < proposed);
    let current_part = &page.body[current..proposed];
    let proposed_part = &page.body[proposed..];
    for expected in [
        "Registered addresses",
        "Address line",
        CURRENT_LINE_A,
        "PS-100",
    ] {
        assert!(current_part.contains(expected), "{expected}: {}", page.body);
    }
    for expected in ["New address line", "New town", PROPOSED_LOCALITY, "PS-205"] {
        assert!(
            proposed_part.contains(expected),
            "{expected}: {}",
            page.body
        );
    }
    // The reference is how the page found the record, not a value to confirm.
    assert!(!page.body.contains(ADDRESS_A));
}

#[test]
fn the_mock_registry_answers_valid_caller_filtered_metadata() {
    let bytes = serde_json::to_vec(&support::metadata()).unwrap();
    let metadata = registry_breg_client::BRegMetadata::from_slice(&bytes).unwrap();
    let get = metadata
        .operations()
        .iter()
        .find(|operation| operation.identifier() == "records.address-correction-request.get")
        .unwrap();
    let address = get
        .fields()
        .iter()
        .find(|field| field.identifier() == support::TARGET_FIELD)
        .unwrap();
    assert_eq!(
        address.reference_target_entity(),
        Some(support::TARGET_ENTITY)
    );
}

#[tokio::test]
async fn t7_double_submit_has_one_effect() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    let form = [("csrf", csrf.as_str()), ("view", view.as_str())];
    let path = submit_path();

    let (first, second) = tokio::join!(
        harness.post(&path, Some(&cookie), &form),
        harness.post(&path, Some(&cookie), &form),
    );
    for outcome in [&first, &second] {
        assert_eq!(outcome.status, StatusCode::OK, "{}", outcome.body);
        assert!(outcome.body.contains("data-outcome=\"submitted\""));
    }
    let third = harness.post(&submit_path(), Some(&cookie), &form).await;
    assert_eq!(third.status, StatusCode::OK, "{}", third.body);

    assert_eq!(harness.environment.registry.submits(), 3);
    assert_eq!(harness.environment.registry.submit_effects(), 1);
}

#[tokio::test]
async fn rendered_record_values_are_inert_markup() {
    let harness = Harness::start().await;
    let (_, page) = harness.review().await;

    assert!(!page.body.contains(HOSTILE_STREET));
    assert!(!page.body.contains("<script"));
    assert!(page.body.contains("&lt;script&gt;"));
    assert!(page.body.contains("New address line"));
    assert!(page.body.contains("Moved house"));
    assert!(!page.body.contains("relocation"));
    assert!(page.body.contains("Not provided"));
    assert!(page.body.contains("Address correction requests"));
}

#[tokio::test]
async fn every_response_carries_the_exact_security_headers() {
    let harness = Harness::start().await;
    let (cookie, review) = harness.review().await;
    let not_found = harness
        .get(&format!("/requests/{OTHER_REQUEST_ID}"), Some(&cookie))
        .await;
    let redirect = harness.get(&review_path(), None).await;
    let health = harness.get("/health", None).await;
    let stylesheet = harness.get("/review.css", None).await;

    for page in [&review, &not_found, &redirect, &health, &stylesheet] {
        assert_eq!(page.header("content-security-policy"), Some(EXPECTED_CSP));
        assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
        assert_eq!(page.header("x-frame-options"), Some("DENY"));
        assert_eq!(
            page.header("cross-origin-opener-policy"),
            Some("same-origin")
        );
        // Development loopback has no TLS, so no HSTS.
        assert!(page.header("strict-transport-security").is_none());
    }
    for page in [&review, &not_found, &redirect, &health] {
        assert_eq!(page.header("cache-control"), Some("no-store"));
    }
    for page in [&review, &not_found] {
        assert_eq!(
            page.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert!(!page.body.contains("<script"));
        assert!(!page.body.contains(" style=\""));
    }
    assert_eq!(stylesheet.status, StatusCode::OK);
    assert_eq!(
        stylesheet.header("content-type"),
        Some("text/css; charset=utf-8")
    );
    assert!(review.body.contains("href=\"/review.css\""));
}

#[tokio::test]
async fn development_cookies_are_http_only_and_same_site() {
    let harness = Harness::start().await;
    let start = harness.get(&sign_in_location(), None).await;
    let sign_in = start.set_cookie("breg-review-signin").unwrap();
    assert_attributes(&sign_in, "Lax");
    assert!(sign_in.contains("Max-Age=600"));

    let callback = harness.sign_in_page(CITIZEN_A).await;
    let session = callback.set_cookie("breg-review-session").unwrap();
    assert_attributes(&session, "Strict");
    let cleared = callback.set_cookie("breg-review-signin").unwrap();
    assert!(cleared.contains("Max-Age=0"));
    assert_eq!(
        cookie_pair(&session).len(),
        "breg-review-session=".len() + 43
    );
}

fn assert_attributes(cookie: &str, same_site: &str) {
    let attributes: Vec<&str> = cookie.split("; ").skip(1).collect();
    assert!(attributes.contains(&"Path=/"), "{cookie}");
    assert!(attributes.contains(&"HttpOnly"), "{cookie}");
    assert!(
        attributes.contains(&format!("SameSite={same_site}").as_str()),
        "{cookie}"
    );
    // Plain loopback HTTP cannot carry a Secure cookie; production can.
    assert!(!attributes.contains(&"Secure"), "{cookie}");
    assert!(!attributes.iter().any(|value| value.starts_with("Domain")));
}

#[tokio::test]
async fn the_callback_continues_to_the_return_path_without_script() {
    let harness = Harness::start().await;
    let callback = harness.sign_in_page(CITIZEN_A).await;

    assert_eq!(callback.status, StatusCode::OK);
    assert!(callback.body.contains(&format!(
        "<meta http-equiv=\"refresh\" content=\"0;url=/requests/{REQUEST_ID}\">"
    )));
    assert!(callback
        .body
        .contains(&format!("href=\"/requests/{REQUEST_ID}\"")));
    assert!(!callback.body.contains("<script"));
}

#[tokio::test]
async fn health_and_ready_answer() {
    let harness = Harness::start().await;
    let health = harness.get("/health", None).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.body, "{\"status\":\"alive\"}");
    let ready = harness.get("/ready", None).await;
    assert_eq!(ready.status, StatusCode::OK);
    assert_eq!(ready.body, "{\"status\":\"ready\"}");
}

#[tokio::test]
async fn the_session_ends_with_the_access_token() {
    let harness = Harness::start_with(Options {
        token_lifetime: Duration::from_secs(2),
        ..Options::default()
    })
    .await;
    let (cookie, _) = harness.review().await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let calls = harness.environment.registry.total_calls();

    let expired = harness.get(&review_path(), Some(&cookie)).await;

    assert_eq!(expired.status, StatusCode::SEE_OTHER);
    assert_eq!(expired.location(), sign_in_location());
    assert_eq!(harness.environment.registry.total_calls(), calls);
}

#[tokio::test]
async fn sign_out_requires_csrf_and_ends_the_session() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();

    let refused = harness.post("/signout", Some(&cookie), &[]).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.error_code(), Some("csrf-refused"));
    let still = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(still.status, StatusCode::OK);

    let signed_out = harness
        .post("/signout", Some(&cookie), &[("csrf", &csrf)])
        .await;
    assert_eq!(signed_out.status, StatusCode::OK);
    assert!(signed_out.body.contains("data-outcome=\"signed-out\""));
    let cleared = signed_out.set_cookie("breg-review-session").unwrap();
    assert!(cleared.contains("Max-Age=0"));
    let after = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(after.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn unauthenticated_submit_links_to_sign_in_without_a_registry_call() {
    let harness = Harness::start().await;
    let page = harness
        .post(&submit_path(), None, &[("csrf", "x"), ("view", "y")])
        .await;
    assert_links_to_sign_in(&page);
    assert_eq!(harness.environment.registry.total_calls(), 0);
}

#[tokio::test]
async fn an_expired_session_posts_answer_pages_not_redirects() {
    let harness = Harness::start_with(Options {
        token_lifetime: Duration::from_secs(2),
        ..Options::default()
    })
    .await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let calls = harness.environment.registry.total_calls();

    let submit = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_links_to_sign_in(&submit);

    let signed_out = harness
        .post("/signout", Some(&cookie), &[("csrf", &csrf)])
        .await;
    assert_eq!(signed_out.status, StatusCode::OK);
    assert!(signed_out.header("location").is_none());
    assert!(signed_out.body.contains("data-outcome=\"signed-out\""));
    assert_eq!(harness.environment.registry.total_calls(), calls);
}

#[tokio::test]
async fn a_submit_the_registry_signs_out_links_to_sign_in_and_ends_the_session() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    harness.environment.registry.refuse_tokens();

    let submit = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_links_to_sign_in(&submit);
    let cleared = submit.set_cookie("breg-review-session").unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert_eq!(harness.environment.registry.submits(), 0);

    // A navigation may still redirect: only a form post may not.
    let read = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(read.status, StatusCode::SEE_OTHER);
    assert_eq!(read.location(), sign_in_location());
}

#[tokio::test]
async fn a_non_canonical_request_identifier_is_not_found_before_sign_in() {
    let harness = Harness::start().await;
    for path in [
        format!("/requests/{}", REQUEST_ID.to_ascii_uppercase()),
        "/requests/not-a-request".to_owned(),
        format!("/requests/{{{REQUEST_ID}}}"),
    ] {
        let page = harness.get(&path, None).await;
        assert_eq!(page.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(page.error_code(), Some("not-found"));
    }
}

#[tokio::test]
async fn a_callback_with_a_wrong_state_or_no_sign_in_cookie_is_refused() {
    let harness = Harness::start().await;
    for tamper in [true, false] {
        let start = harness.get(&sign_in_location(), None).await;
        let sign_in_cookie = cookie_pair(&start.set_cookie("breg-review-signin").unwrap());
        let authorize = format!("{}&login_hint={CITIZEN_A}", start.location());
        let redirected = harness.http.get(authorize).send().await.unwrap();
        let mut callback = redirected
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let cookie = if tamper {
            callback = callback.replacen("state=", "state=x", 1);
            Some(sign_in_cookie.as_str())
        } else {
            None
        };
        let mut request = harness.http.get(&callback);
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let page = support::page(request.send().await.unwrap()).await;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{tamper}");
        assert_eq!(page.error_code(), Some("sign-in-refused"));
        assert!(page.set_cookie("breg-review-session").is_none());
    }
}

#[tokio::test]
async fn a_sign_in_cookie_is_single_use() {
    let harness = Harness::start().await;
    let start = harness.get(&sign_in_location(), None).await;
    let sign_in_cookie = cookie_pair(&start.set_cookie("breg-review-signin").unwrap());
    let authorize = format!("{}&login_hint={CITIZEN_A}", start.location());
    let redirected = harness.http.get(authorize).send().await.unwrap();
    let callback = redirected
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let send = || async {
        support::page(
            harness
                .http
                .get(&callback)
                .header("cookie", &sign_in_cookie)
                .send()
                .await
                .unwrap(),
        )
        .await
    };
    assert_eq!(send().await.status, StatusCode::OK);
    let replay = send().await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.error_code(), Some("sign-in-refused"));
}

#[tokio::test]
async fn the_authorization_request_carries_pkce_state_nonce_and_resource() {
    let harness = Harness::start().await;
    let start = harness.get(&sign_in_location(), None).await;
    let location = url::Url::parse(start.location()).unwrap();
    let pairs: std::collections::BTreeMap<String, String> =
        location.query_pairs().into_owned().collect();
    assert_eq!(pairs["response_type"], "code");
    assert_eq!(pairs["client_id"], support::CLIENT_ID);
    assert_eq!(pairs["code_challenge_method"], "S256");
    assert_eq!(pairs["code_challenge"].len(), 43);
    assert_eq!(pairs["state"].len(), 43);
    assert_eq!(pairs["nonce"].len(), 43);
    assert_eq!(pairs["resource"], support::RESOURCE);
    assert_eq!(pairs["scope"], format!("openid {}", support::SCOPE));
    assert_eq!(
        pairs["redirect_uri"],
        format!("{}/signin/callback", harness.environment.origin)
    );
}

#[tokio::test]
async fn unknown_paths_methods_and_oversized_bodies_are_html() {
    let harness = Harness::start().await;
    let missing = harness.get("/nowhere", None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.error_code(), Some("not-found"));
    assert_eq!(
        missing.header("content-type"),
        Some("text/html; charset=utf-8")
    );

    let method = support::page(
        harness
            .http
            .put(harness.url(&review_path()))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(method.error_code(), Some("method-not-allowed"));

    let (cookie, _) = harness.review().await;
    let large = "a".repeat(64 * 1024);
    let oversized = harness
        .post(&submit_path(), Some(&cookie), &[("csrf", &large)])
        .await;
    assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(oversized.error_code(), Some("request-too-large"));
    assert_eq!(
        oversized.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        oversized.header("content-security-policy"),
        Some(EXPECTED_CSP)
    );
}

#[tokio::test]
async fn the_audit_journal_names_pseudonyms_actions_and_outcomes() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    let submitted = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(submitted.status, StatusCode::OK);

    let journal = harness.environment.audit_text();
    let records: Vec<serde_json::Value> = journal
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["record"].clone())
        .collect();
    let find = |action: &str, outcome: &str| {
        records
            .iter()
            .find(|record| record["action"] == action && record["outcome"] == outcome)
            .unwrap_or_else(|| panic!("no {action} {outcome} record in {journal}"))
    };
    let signed_in = find("sign-in", "succeeded");
    let read = find("read", "succeeded");
    find("submit", "attempted");
    let submit = find("submit", "succeeded");
    assert_eq!(read["requestId"], REQUEST_ID);
    assert_eq!(submit["requestId"], REQUEST_ID);
    assert_eq!(signed_in["citizenPseudonym"], read["citizenPseudonym"]);
    assert!(read["citizenPseudonym"].as_str().unwrap().len() >= 32);
    assert!(read["clientPseudonym"].as_str().unwrap().len() >= 32);
    // Behind a proxy every browser shares one peer address, so the journal
    // does not name it.
    for record in &records {
        assert!(record.get("addressPseudonym").is_none(), "{record}");
    }
    assert!(!journal.contains(CITIZEN_A));
    assert!(!journal.contains(support::CLIENT_ID));
    assert!(!journal.contains(&csrf));
    assert!(!journal.contains(&cookie_pair(&cookie)[("breg-review-session=".len())..]));
}

/// A page whose unauthenticated routes admit `global_burst` requests and whose
/// signed-in people each admit `citizen_burst`, both refilling once a minute.
async fn limited(global_burst: u32, citizen_burst: u32) -> Harness {
    Harness::start_with(Options {
        extra_document: format!(
            "limits:\n  globalSignIn: {{ requestsPerMinute: 1, burst: {global_burst} }}\n  \
             perCitizen: {{ requestsPerMinute: 1, burst: {citizen_burst} }}\n"
        ),
        ..Options::default()
    })
    .await
}

#[tokio::test]
async fn a_session_over_its_own_limit_is_refused_while_another_proceeds() {
    // Two sign-ins, a start and a callback each, spend the whole global cap:
    // behind a proxy every browser shares it, so it must not also limit
    // signed-in people.
    let harness = limited(4, 2).await;
    let a = cookie_pair(&harness.sign_in(CITIZEN_A).await);
    let b = cookie_pair(&harness.sign_in(CITIZEN_B).await);

    for _ in 0..2 {
        let page = harness.get(&review_path(), Some(&a)).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    }
    let refused = harness.get(&review_path(), Some(&a)).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.error_code(), Some("rate-limited"));
    assert!(refused.header("retry-after").is_some());

    let other = harness
        .get(&format!("/requests/{B_REQUEST_ID}"), Some(&b))
        .await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.body);
}

#[tokio::test]
async fn the_global_cap_still_limits_sign_in_starts() {
    let harness = limited(3, 30).await;
    let a = cookie_pair(&harness.sign_in(CITIZEN_A).await);
    let start = format!("/signin?return=%2Frequests%2F{REQUEST_ID}");

    let admitted = harness.get(&start, None).await;
    assert_eq!(admitted.status, StatusCode::SEE_OTHER, "{}", admitted.body);
    let refused = harness.get(&start, None).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.error_code(), Some("rate-limited"));
    assert!(refused.header("retry-after").is_some());
    assert!(refused.set_cookie("breg-review-signin").is_none());

    // A signed-in person draws on their own limit, not the global one.
    let page = harness.get(&review_path(), Some(&a)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
}

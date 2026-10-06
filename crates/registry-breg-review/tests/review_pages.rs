// SPDX-License-Identifier: Apache-2.0
//! The review page over loopback HTTP, against an in-process authorization
//! server and a stateful mock registry.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use registry_breg_client::BRegProblemCode;
use support::{
    browser, cookie_pair, sign_in_to, start_narrow_scope_provider, write_secret, AuditSink,
    Harness, Options, ADDRESS_A, B_REQUEST_ID, CITIZEN_A, CITIZEN_B, CLIENT_ID, CURRENT_LINE_A,
    ENTITY, EXPECTED_CSP, FOREIGN_TARGET_REQUEST_ID, HOSTILE_STREET, OTHER_REQUEST_ID, PROFILE,
    PROPOSED_LOCALITY, REQUEST_ID, RESOURCE, SCOPE, TARGET_FIELD,
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
async fn a_target_changed_since_the_render_rerenders_and_asks_again() {
    const CHANGED_LINE: &str = "9 Quay Street";
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    assert!(page.body.contains(CURRENT_LINE_A), "{}", page.body);
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();

    // The draft is untouched, so its action's precondition still holds: only
    // the page can notice that the values the person saw are gone.
    harness
        .environment
        .registry
        .change_address(ADDRESS_A, CHANGED_LINE);
    let stale = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;

    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.body);
    assert!(stale.body.contains("data-notice=\"request-changed\""));
    assert!(stale.body.contains(CHANGED_LINE), "{}", stale.body);
    assert_eq!(harness.environment.registry.submits(), 0);
    let fresh_view = stale.input("view").expect("the re-render asks again");
    assert_ne!(fresh_view, view);

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
async fn a_conflicted_submit_rerenders_from_a_fresh_read_not_the_stale_one() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();

    // Between the page's load and this submit, the draft changed (so the
    // submit conflicts), and the moment it conflicts the target address
    // stops being readable too. The submit's own read at the top of the
    // POST still sees the address; only a fresh read after the conflict
    // would see it gone.
    harness.environment.registry.agent_patch();
    harness
        .environment
        .registry
        .withdraw_reader_on_next_conflict(ADDRESS_A);

    let stale = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;

    assert_eq!(stale.status, StatusCode::NOT_FOUND, "{}", stale.body);
    assert_eq!(stale.error_code(), Some("not-found"));
}

#[tokio::test]
async fn a_conflicted_submit_is_journaled_refused() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();

    // A view this session never rendered, then a draft that changed under
    // the rendered view: both conflict before any effect.
    harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", "unrendered")],
        )
        .await;
    harness.environment.registry.agent_patch();
    let stale = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.body);
    assert_eq!(harness.environment.registry.submit_effects(), 0);

    let mut submit_outcomes = Vec::new();
    for _ in 0..100 {
        submit_outcomes = harness
            .environment
            .audit_text()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|entry| entry["phase"] == "response" && entry["record"]["action"] == "submit")
            .map(|entry| entry["record"]["outcome"].clone())
            .collect();
        if submit_outcomes.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(submit_outcomes, ["refused", "refused"]);
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

#[tokio::test]
async fn the_target_read_is_the_profile_get_whatever_reference_comes_first() {
    let harness = Harness::start().await;
    harness.environment.registry.publish_target_list_first();
    let (_, page) = harness.review().await;
    assert!(page.body.contains(CURRENT_LINE_A), "{}", page.body);
    assert_eq!(harness.environment.registry.target_reads(ADDRESS_A), 1);
}

#[test]
fn the_mock_registry_answers_valid_caller_filtered_metadata() {
    let bytes = serde_json::to_vec(&support::metadata_with_target_list_first()).unwrap();
    registry_breg_client::BRegMetadata::from_slice(&bytes).unwrap();
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
async fn an_uncertain_submit_retries_the_original_action_and_idempotency_key_once() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    let form = [("csrf", csrf.as_str()), ("view", view.as_str())];
    harness
        .environment
        .registry
        .lose_next_submit_response_after_commit();

    let uncertain = harness.post(&submit_path(), Some(&cookie), &form).await;
    assert_eq!(
        uncertain.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        uncertain.body
    );
    assert_eq!(uncertain.error_code(), Some("registry-unavailable"));
    assert_eq!(harness.environment.registry.submit_effects(), 1);

    let replay = harness.post(&submit_path(), Some(&cookie), &form).await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert!(replay.body.contains("data-outcome=\"submitted\""));
    assert_eq!(harness.environment.registry.submits(), 2);
    assert_eq!(harness.environment.registry.submit_effects(), 1);

    let mut journal = String::new();
    for _ in 0..100 {
        journal = harness.environment.audit_text();
        if journal.contains("\"outcome\":\"unfinished\"") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let submit_responses: Vec<_> = journal
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|entry| entry["phase"] == "response" && entry["record"]["action"] == "submit")
        .collect();
    assert_eq!(submit_responses.len(), 2, "{journal}");
    assert!(submit_responses
        .iter()
        .any(|entry| entry["record"]["outcome"] == "unfinished"));
    assert!(submit_responses
        .iter()
        .any(|entry| entry["record"]["outcome"] == "ok"));
}

/// A retry after the receipt horizon meets a key the registry keeps spent:
/// the first submit committed and nothing runs again. The page must not say
/// nothing changed, nor invite another try of the same key.
#[tokio::test]
async fn a_retry_past_the_receipt_horizon_is_a_definite_conflict() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    let form = [("csrf", csrf.as_str()), ("view", view.as_str())];
    harness
        .environment
        .registry
        .lose_next_submit_response_after_commit();
    let uncertain = harness.post(&submit_path(), Some(&cookie), &form).await;
    assert_eq!(uncertain.error_code(), Some("registry-unavailable"));
    harness.environment.registry.expire_receipts();

    let expired = harness.post(&submit_path(), Some(&cookie), &form).await;
    assert_eq!(expired.status, StatusCode::CONFLICT, "{}", expired.body);
    assert_eq!(expired.error_code(), Some("request-conflict"));
    assert!(
        !expired.body.contains("nothing was changed"),
        "{}",
        expired.body
    );
    assert!(!expired.body.contains("Try again"), "{}", expired.body);
    assert_eq!(harness.environment.registry.submits(), 2);
    assert_eq!(harness.environment.registry.submit_effects(), 1);

    let mut outcomes = Vec::new();
    for _ in 0..100 {
        outcomes = response_outcomes(&harness.environment.audit_text(), "submit");
        if outcomes.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    outcomes.sort();
    assert_eq!(outcomes, ["refused", "unfinished"]);
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
async fn readiness_reports_not_ready_when_the_audit_journal_is_not_writable() {
    use std::os::unix::fs::PermissionsExt;

    let harness = Harness::start().await;
    let audit_path = &harness.environment.audit_path;
    let original = std::fs::metadata(audit_path)
        .expect("audit file metadata")
        .permissions();
    std::fs::set_permissions(audit_path, std::fs::Permissions::from_mode(0o644))
        .expect("audit file permissions widen");

    let ready = harness.get("/ready", None).await;
    assert_eq!(ready.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready.body, "{\"status\":\"not-ready\"}");

    std::fs::set_permissions(audit_path, original).expect("audit file permissions restore");
}

#[tokio::test]
async fn an_audit_request_failure_prevents_registry_io() {
    use std::os::unix::fs::PermissionsExt;

    let harness = Harness::start().await;
    let (cookie, _) = harness.review().await;
    let calls = harness.environment.registry.total_calls();
    let audit_path = &harness.environment.audit_path;
    let original = std::fs::metadata(audit_path).unwrap().permissions();
    std::fs::set_permissions(audit_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let refused = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.error_code(), Some("audit-unavailable"));
    assert_eq!(harness.environment.registry.total_calls(), calls);

    std::fs::set_permissions(audit_path, original).unwrap();
}

#[tokio::test]
async fn a_terminal_audit_refusal_withholds_the_protected_page() {
    use std::os::unix::fs::PermissionsExt;

    let harness = Harness::start().await;
    let (cookie, _) = harness.review().await;
    let registry = &harness.environment.registry;
    registry.pause_next_metadata_response();
    let audit_path = &harness.environment.audit_path;
    let original = std::fs::metadata(audit_path).unwrap().permissions();

    let path = review_path();
    let request = harness.get(&path, Some(&cookie));
    let break_terminal_audit = async {
        registry.wait_until_metadata_response_is_paused().await;
        std::fs::set_permissions(audit_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        registry.release_metadata_response();
    };
    let (withheld, ()) = tokio::join!(request, break_terminal_audit);

    assert_eq!(withheld.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(withheld.error_code(), Some("audit-unavailable"));
    assert!(!withheld.body.contains(CURRENT_LINE_A), "{}", withheld.body);
    assert!(withheld.input("view").is_none());

    std::fs::set_permissions(audit_path, original).unwrap();
}

#[tokio::test]
async fn the_session_ends_with_the_access_token() {
    let harness = Harness::start_with(Options {
        token_lifetime: Duration::from_secs(10),
        ..Options::default()
    })
    .await;
    let (cookie, _) = harness.review().await;
    tokio::time::sleep(Duration::from_millis(10_500)).await;
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

    let journal = harness.environment.audit_text();
    let sign_out: Vec<serde_json::Value> = journal
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|entry: &serde_json::Value| entry["record"]["action"] == "sign-out")
        .collect();
    assert_eq!(sign_out.len(), 2, "{journal}");
    assert_eq!(sign_out[0]["phase"], "request");
    assert_eq!(sign_out[1]["phase"], "response");
    assert_eq!(sign_out[1]["record"]["outcome"], "ok");
    assert_eq!(sign_out[0]["correlation"], sign_out[1]["correlation"]);
}

#[tokio::test]
async fn a_sign_out_request_audit_refusal_preserves_the_session() {
    use std::os::unix::fs::PermissionsExt;

    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let audit_path = &harness.environment.audit_path;
    let original = std::fs::metadata(audit_path).unwrap().permissions();
    std::fs::set_permissions(audit_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let refused = harness
        .post("/signout", Some(&cookie), &[("csrf", &csrf)])
        .await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.error_code(), Some("audit-unavailable"));
    assert!(refused.set_cookie("breg-review-session").is_none());

    std::fs::set_permissions(audit_path, original).unwrap();
    // The failed writer stays failed. A retained session reaches the audit
    // gate; a removed session would redirect before it.
    let still_present = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(still_present.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(still_present.error_code(), Some("audit-unavailable"));
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
        token_lifetime: Duration::from_secs(10),
        ..Options::default()
    })
    .await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    tokio::time::sleep(Duration::from_millis(10_500)).await;
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
    let journal = harness.environment.audit_text();
    assert!(
        !journal.lines().any(|line| {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            entry["record"]["action"] == "sign-in"
        }),
        "{journal}"
    );
}

#[tokio::test]
async fn a_valid_provider_error_callback_is_audited_as_refused() {
    let harness = Harness::start().await;
    let start = harness.get(&sign_in_location(), None).await;
    let sign_in_cookie = cookie_pair(&start.set_cookie("breg-review-signin").unwrap());
    let redirected = harness
        .http
        .get(format!("{}&login_hint={CITIZEN_A}", start.location()))
        .send()
        .await
        .unwrap();
    let callback = url::Url::parse(redirected.headers()["location"].to_str().unwrap()).unwrap();
    let returned: std::collections::BTreeMap<String, String> =
        callback.query_pairs().into_owned().collect();
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("error", "access_denied");
    query.append_pair("state", &returned["state"]);
    if let Some(issuer) = returned.get("iss") {
        query.append_pair("iss", issuer);
    }
    let path = format!("/signin/callback?{}", query.finish());

    let refused = harness.get(&path, Some(&sign_in_cookie)).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.error_code(), Some("sign-in-refused"));
    assert!(refused.set_cookie("breg-review-session").is_none());

    let journal = harness.environment.audit_text();
    let entries: Vec<serde_json::Value> = journal
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|entry: &serde_json::Value| entry["record"]["action"] == "sign-in")
        .collect();
    assert_eq!(entries.len(), 2, "{journal}");
    assert_eq!(entries[0]["phase"], "request");
    assert!(entries[0]["record"].get("outcome").is_none());
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[1]["record"]["outcome"], "refused");
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
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
    let entries: Vec<serde_json::Value> = journal
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect();
    let records: Vec<_> = entries.iter().map(|entry| &entry["record"]).collect();
    let find = |action: &str, outcome: &str| {
        records
            .iter()
            .find(|record| record["action"] == action && record["outcome"] == outcome)
            .unwrap_or_else(|| panic!("no {action} {outcome} record in {journal}"))
    };
    let signed_in = find("sign-in", "ok");
    let read = find("read", "ok");
    let submit = find("submit", "ok");
    let submit_request = entries
        .iter()
        .find(|entry| entry["phase"] == "request" && entry["record"]["action"] == "submit")
        .expect("submit request audit entry");
    assert!(submit_request["record"].get("outcome").is_none());
    let submit_response = entries
        .iter()
        .find(|entry| {
            entry["phase"] == "response"
                && entry["record"]["action"] == "submit"
                && entry["record"]["outcome"] == "ok"
        })
        .expect("submit response audit entry");
    assert_eq!(
        submit_request["correlation"],
        submit_response["correlation"]
    );
    // The change request is named `changeRequestId`, so it cannot be joined
    // with the gateway's per-call `requestId`, and the person is named by the
    // same `principalPseudonym` key the registry's audit uses.
    assert_eq!(read["changeRequestId"], REQUEST_ID);
    assert_eq!(submit["changeRequestId"], REQUEST_ID);
    assert_eq!(signed_in["principalPseudonym"], read["principalPseudonym"]);
    assert!(read["principalPseudonym"].as_str().unwrap().len() >= 32);
    for record in &records {
        assert!(record.get("requestId").is_none(), "{record}");
        assert!(record.get("citizenPseudonym").is_none(), "{record}");
    }
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

#[tokio::test]
async fn a_throttled_callback_ends_the_sign_in_whose_cookie_it_clears() {
    // Two sign-in requests in a burst, refilling one a second.
    let harness = Harness::start_with(Options {
        extra_document: "limits:\n  globalSignIn: { requestsPerMinute: 60, burst: 2 }\n".to_owned(),
        ..Options::default()
    })
    .await;
    let start = harness.get(&sign_in_location(), None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.body);
    let sign_in_cookie = cookie_pair(&start.set_cookie("breg-review-signin").unwrap());
    let redirected = harness
        .http
        .get(format!("{}&login_hint={CITIZEN_A}", start.location()))
        .send()
        .await
        .unwrap();
    let callback = redirected.headers()["location"]
        .to_str()
        .unwrap()
        .to_owned();
    let send_callback = || async {
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
    // Someone else's sign-in start spends the rest of the burst.
    let other = harness.get(&sign_in_location(), None).await;
    assert_eq!(other.status, StatusCode::SEE_OTHER, "{}", other.body);

    let throttled = send_callback().await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(throttled.error_code(), Some("rate-limited"));
    let retry_after: u64 = throttled.header("retry-after").unwrap().parse().unwrap();
    let cleared = throttled.set_cookie("breg-review-signin").unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    // The browser no longer holds the cookie, so the pending sign-in behind
    // it must be gone too: presenting it once the limit refills finds
    // nothing to complete.
    tokio::time::sleep(Duration::from_secs(retry_after)).await;
    let retried = send_callback().await;
    assert_eq!(retried.status, StatusCode::BAD_REQUEST, "{}", retried.body);
    assert_eq!(retried.error_code(), Some("sign-in-refused"));
    assert!(retried.set_cookie("breg-review-session").is_none());
}

/// A page whose session store holds at most `maximum_sessions` sessions.
async fn limited_sessions(maximum_sessions: u32) -> Harness {
    Harness::start_with(Options {
        extra_document: format!("session:\n  maximumSessions: {maximum_sessions}\n"),
        ..Options::default()
    })
    .await
}

#[tokio::test]
async fn a_sign_in_when_sessions_are_full_records_no_succeeded_sign_in() {
    let harness = limited_sessions(1).await;
    harness.sign_in(CITIZEN_A).await;

    // The one session slot is already spent, so this callback cannot open a
    // second session. It must not have audited one either: the audit and
    // the session it describes stand or fall together.
    let second = harness.sign_in_page(CITIZEN_B).await;
    assert_eq!(
        second.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        second.body
    );
    assert_eq!(second.error_code(), Some("sessions-exhausted"));
    assert!(second.set_cookie("breg-review-session").is_none());

    let journal = harness.environment.audit_text();
    let succeeded_sign_ins = journal
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["record"].clone())
        .filter(|record| record["action"] == "sign-in" && record["outcome"] == "ok")
        .count();
    assert_eq!(succeeded_sign_ins, 1, "{journal}");
    let refused_sign_ins = journal
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["record"].clone())
        .filter(|record| record["action"] == "sign-in" && record["outcome"] == "refused")
        .count();
    assert_eq!(refused_sign_ins, 1, "{journal}");
}

/// How many sessions one citizen holds at once, as the README states.
const SESSIONS_PER_CITIZEN: usize = 3;

#[tokio::test]
async fn one_citizen_signing_in_again_and_again_holds_a_bounded_share_of_sessions() {
    // Room for one citizen's share and one more session.
    let harness = limited_sessions(u32::try_from(SESSIONS_PER_CITIZEN + 1).unwrap()).await;

    // Every sign-in past the share replaces the citizen's oldest session
    // rather than take another slot, so none of them is refused.
    for attempt in 0..3 * SESSIONS_PER_CITIZEN {
        let page = harness.sign_in_page(CITIZEN_A).await;
        assert_eq!(
            page.status,
            StatusCode::OK,
            "attempt {attempt}: {}",
            page.body
        );
        assert!(page.set_cookie("breg-review-session").is_some());
    }

    // The one slot beyond that share is still free for another citizen.
    let other = harness.sign_in_page(CITIZEN_B).await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.body);
    assert!(other.set_cookie("breg-review-session").is_some());

    // The first citizen holds exactly their share: with the store now
    // full, a third citizen is refused.
    let third = harness.sign_in_page("citizen-c").await;
    assert_eq!(
        third.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        third.body
    );
    assert_eq!(third.error_code(), Some("sessions-exhausted"));
}

#[tokio::test]
async fn a_session_replaced_by_the_same_citizen_signing_in_again_is_refused() {
    let harness = Harness::start().await;
    let mut cookies = Vec::new();
    for _ in 0..=SESSIONS_PER_CITIZEN {
        cookies.push(cookie_pair(&harness.sign_in(CITIZEN_A).await));
    }
    let calls = harness.environment.registry.total_calls();

    let evicted = harness.get(&review_path(), Some(&cookies[0])).await;
    assert_eq!(evicted.status, StatusCode::SEE_OTHER, "{}", evicted.body);
    assert_eq!(evicted.location(), sign_in_location());
    assert_eq!(harness.environment.registry.total_calls(), calls);

    for cookie in &cookies[1..] {
        let live = harness.get(&review_path(), Some(cookie)).await;
        assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    }
}

#[tokio::test]
async fn an_audit_failure_during_sign_in_leaves_no_session_behind() {
    use std::os::unix::fs::PermissionsExt;

    let harness = limited_sessions(1).await;
    let audit_path = &harness.environment.audit_path;
    let original = std::fs::metadata(audit_path)
        .expect("audit file metadata")
        .permissions();
    std::fs::set_permissions(audit_path, std::fs::Permissions::from_mode(0o644))
        .expect("audit file permissions widen");

    let first = harness.sign_in_page(CITIZEN_A).await;
    assert_eq!(
        first.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        first.body
    );
    assert_eq!(first.error_code(), Some("audit-unavailable"));
    assert!(first.set_cookie("breg-review-session").is_none());

    // The audit sink refuses every write for the rest of this process once
    // one durable write has failed, so this second sign-in fails on the
    // audit too, never on session capacity. If the first attempt's session
    // had leaked, the one slot would already be spent and this would report
    // sessions-exhausted instead.
    let second = harness.sign_in_page(CITIZEN_B).await;
    assert_eq!(
        second.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        second.body
    );
    assert_eq!(second.error_code(), Some("audit-unavailable"));

    std::fs::set_permissions(audit_path, original).expect("audit file permissions restore");
}

/// A sign-in against a provider whose token response states a scope
/// narrower than the one the page asked for is refused at the callback, and
/// opens no session: the provider is minimal on purpose, built only to say
/// less than the request asked for, which the shared `TestAuthorizationServer`
/// never does.
struct CustomIssuerPage {
    _directory: tempfile::TempDir,
    origin: String,
    audit_path: std::path::PathBuf,
    http: reqwest::Client,
}

async fn start_custom_issuer_page(issuer: &str) -> CustomIssuerPage {
    use std::os::unix::fs::PermissionsExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");

    // A loopback port nothing answers on: the callback is refused before the
    // page ever reads the registry, so this address is never dialed.
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registry_base = format!("http://{}/tenant/base", unused.local_addr().unwrap());
    drop(unused);

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
    write_secret(
        &secrets,
        "client-key.jwk",
        registry_platform_testing::fixtures::ED25519_PRIVATE_JWK.as_bytes(),
    );
    write_secret(&secrets, "audit-key", &[0x5a; 32]);
    let audit_directory = root.join("audit");
    std::fs::create_dir(&audit_directory).unwrap();
    std::fs::set_permissions(&audit_directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let audit_path = audit_directory.join("audit.jsonl");
    let config_path = root.join("runtime.yaml");
    let document = format!(
        "apiVersion: registry.registrystack.org/breg-review-runtime/v1alpha1\n\
         kind: BRegReviewRuntimeConfig\n\
         listener:\n  bind: \"{address}\"\n  tlsTermination: development-loopback\n\
         publicOrigin: {origin}\n\
         secretProviders:\n  file:\n    root: {secrets}\n\
         signIn:\n  issuer: {issuer}\n  clientId: {CLIENT_ID}\n  clientKeyRef: secret:file/client-key.jwk\n  scopes: [\"{SCOPE}\"]\n\
         registry:\n  baseUrl: {registry_base}\n  resource: {RESOURCE}\n  entity: {ENTITY}\n  targetField: {TARGET_FIELD}\n  accessProfile: {PROFILE}\n\
         audit:\n  path: {audit}\n  hashKeyRef: secret:file/audit-key\n",
        secrets = secrets.display(),
        audit = audit_path.display(),
    );
    std::fs::write(&config_path, document).unwrap();

    let config =
        registry_breg_review::RuntimeConfig::load(&config_path).expect("runtime document loads");
    let router = registry_breg_review::router(config)
        .await
        .expect("review page starts");
    tokio::spawn(async move {
        registry_breg_review::serve_until(listener, router, std::future::pending())
            .await
            .expect("review page serves");
    });

    CustomIssuerPage {
        _directory: directory,
        origin,
        audit_path,
        http: browser(),
    }
}

#[tokio::test]
async fn a_sign_in_request_audit_refusal_prevents_provider_io() {
    use std::os::unix::fs::PermissionsExt;

    let provider = start_narrow_scope_provider().await;
    let page = start_custom_issuer_page(&provider.issuer).await;
    let start = support::page(
        page.http
            .get(format!(
                "{}/signin?return=%2Frequests%2F{REQUEST_ID}",
                page.origin
            ))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let sign_in_cookie = cookie_pair(&start.set_cookie("breg-review-signin").unwrap());
    let redirected = page
        .http
        .get(format!("{}&login_hint={CITIZEN_A}", start.location()))
        .send()
        .await
        .unwrap();
    let callback = redirected.headers()["location"]
        .to_str()
        .unwrap()
        .to_owned();
    let original = std::fs::metadata(&page.audit_path).unwrap().permissions();
    std::fs::set_permissions(&page.audit_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let refused = support::page(
        page.http
            .get(&callback)
            .header("cookie", sign_in_cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.error_code(), Some("audit-unavailable"));
    assert!(refused.set_cookie("breg-review-session").is_none());
    assert_eq!(provider.token_calls(), 0);
    std::fs::set_permissions(&page.audit_path, original).unwrap();
}

#[tokio::test]
async fn a_narrowed_token_response_is_refused_with_no_session_created() {
    let provider = start_narrow_scope_provider().await;
    let page = start_custom_issuer_page(&provider.issuer).await;

    let response = sign_in_to(&page.http, &page.origin, CITIZEN_A, REQUEST_ID).await;

    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert_eq!(response.error_code(), Some("sign-in-refused"));
    assert!(response.set_cookie("breg-review-session").is_none());
    assert_eq!(provider.token_calls(), 1);
}

/// The terminal outcomes the journal `journal` recorded for `action`.
fn response_outcomes(journal: &str, action: &str) -> Vec<String> {
    journal
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|entry| entry["phase"] == "response" && entry["record"]["action"] == action)
        .map(|entry| entry["record"]["outcome"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_read_the_registry_cannot_answer_is_audited_refused() {
    let harness = Harness::start().await;
    let cookie = harness.sign_in(CITIZEN_A).await;
    harness.environment.registry.fail_next_draft_read();

    let page = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(page.status, StatusCode::BAD_GATEWAY, "{}", page.body);
    assert_eq!(page.error_code(), Some("registry-unavailable"));

    let journal = harness.environment.audit_text();
    assert_eq!(
        response_outcomes(&journal, "read"),
        ["refused"],
        "{journal}"
    );
}

#[tokio::test]
async fn a_submit_the_registry_declines_is_refused_without_retry_advice() {
    for code in [
        BRegProblemCode::ActionRefused,
        BRegProblemCode::RequestInvalid,
    ] {
        let harness = Harness::start().await;
        let (cookie, page) = harness.review().await;
        let csrf = page.input("csrf").unwrap();
        let view = page.input("view").unwrap();
        harness.environment.registry.refuse_next_submit(code);

        let declined = harness
            .post(
                &submit_path(),
                Some(&cookie),
                &[("csrf", &csrf), ("view", &view)],
            )
            .await;
        assert_eq!(
            declined.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            declined.body
        );
        assert_eq!(declined.error_code(), Some("registry-refused"));
        assert!(
            declined.body.contains("nothing was changed"),
            "{}",
            declined.body
        );
        assert!(!declined.body.contains("Try again"), "{}", declined.body);
        assert_eq!(harness.environment.registry.submits(), 1);
        assert_eq!(harness.environment.registry.submit_effects(), 0);

        let journal = harness.environment.audit_text();
        assert_eq!(
            response_outcomes(&journal, "submit"),
            ["refused"],
            "{journal}"
        );
    }
}

#[tokio::test]
async fn a_read_the_registry_declines_is_refused_without_retry_advice() {
    let harness = Harness::start().await;
    let cookie = harness.sign_in(CITIZEN_A).await;
    harness
        .environment
        .registry
        .refuse_next_draft_read(BRegProblemCode::RequestInvalid);

    let page = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(
        page.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        page.body
    );
    assert_eq!(page.error_code(), Some("registry-refused"));

    let journal = harness.environment.audit_text();
    assert_eq!(
        response_outcomes(&journal, "read"),
        ["refused"],
        "{journal}"
    );
}

#[tokio::test]
async fn a_committed_submit_whose_result_cannot_be_audited_is_answered_uncertain() {
    let sink = AuditSink::default();
    let harness = Harness::start_with_audit_sink(&sink).await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    let view = page.input("view").unwrap();
    // The submit's request entry is accepted; its terminal response is not.
    sink.fail_after(1);

    let submit = harness
        .post(
            &submit_path(),
            Some(&cookie),
            &[("csrf", &csrf), ("view", &view)],
        )
        .await;
    assert_eq!(harness.environment.registry.submit_effects(), 1);
    assert_eq!(submit.status, StatusCode::BAD_GATEWAY, "{}", submit.body);
    assert_eq!(submit.error_code(), Some("registry-unavailable"));
    assert!(!submit.body.contains("does nothing"), "{}", submit.body);
}

#[tokio::test]
async fn a_sign_out_whose_result_cannot_be_audited_still_signs_out() {
    let sink = AuditSink::default();
    let harness = Harness::start_with_audit_sink(&sink).await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    // The sign-out's request entry is accepted; its terminal response is not.
    sink.fail_after(1);

    let signed_out = harness
        .post("/signout", Some(&cookie), &[("csrf", &csrf)])
        .await;
    assert_eq!(signed_out.status, StatusCode::OK, "{}", signed_out.body);
    assert!(signed_out.body.contains("data-outcome=\"signed-out\""));
    let cleared = signed_out.set_cookie("breg-review-session").unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    let after = harness.get(&review_path(), Some(&cookie)).await;
    assert_eq!(after.status, StatusCode::SEE_OTHER);
    assert_eq!(after.location(), sign_in_location());
}

#[tokio::test]
async fn a_read_whose_page_cannot_be_rendered_is_not_audited_ok() {
    let harness = Harness::start().await;
    let (cookie, page) = harness.review().await;
    let csrf = page.input("csrf").unwrap();
    harness.environment.registry.pause_next_metadata_response();

    // The session ends while the read waits on the registry, so the page the
    // read loaded can no longer be offered to it.
    let path = review_path();
    let (read, ()) = tokio::join!(harness.get(&path, Some(&cookie)), async {
        harness
            .environment
            .registry
            .wait_until_metadata_response_is_paused()
            .await;
        let signed_out = harness
            .post("/signout", Some(&cookie), &[("csrf", &csrf)])
            .await;
        assert_eq!(signed_out.status, StatusCode::OK, "{}", signed_out.body);
        harness.environment.registry.release_metadata_response();
    });
    assert_eq!(read.status, StatusCode::SEE_OTHER, "{}", read.body);
    assert_eq!(read.location(), sign_in_location());

    let journal = harness.environment.audit_text();
    assert_eq!(
        response_outcomes(&journal, "read"),
        ["ok", "refused"],
        "{journal}"
    );
}

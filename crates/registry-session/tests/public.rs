// SPDX-License-Identifier: Apache-2.0
//! The public routes and the gateway check, end to end over loopback HTTP
//! against an in-process provider.

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use support::{
    audience_of, AuditSink, Harness, Options, CASEWORK_AUDIENCE, CITIZEN_CLIENT,
    DOCUMENTS_AUDIENCE, FLOW_COOKIE, PERSON_AUDIENCE, SESSION_COOKIE, STAFF_CLIENT,
};

fn bearer(page: &support::Page) -> String {
    page.header("authorization")
        .expect("an authorization header")
        .strip_prefix("Bearer ")
        .expect("a bearer token")
        .to_owned()
}

#[tokio::test]
async fn a_citizen_signs_in_in_one_hop() {
    let harness = Harness::start().await;
    let signed_in = harness.sign_in("/apply/start", "citizen-a").await;
    assert_eq!(signed_in.hops, 1);

    let page = &signed_in.page;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.continue_path().as_deref(), Some("/apply/start"));
    assert!(page.body.contains("<a href=\"/apply/start\""));
    assert!(!page.body.contains("<script"));
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(
        page.header("content-security-policy"),
        Some("default-src 'none'; frame-ancestors 'none'")
    );
    assert!(!page.marked());

    let session = page.set_cookie(SESSION_COOKIE).expect("session cookie");
    for attribute in ["HttpOnly", "SameSite=Lax", "Path=/", "Max-Age="] {
        assert!(session.contains(attribute), "{attribute}");
    }
    assert!(!session.contains("Domain"));
    let cleared = page.set_cookie(FLOW_COOKIE).expect("flow cookie cleared");
    assert!(cleared.contains("Max-Age=0"));

    let me = harness.get("/session/me", Some(&signed_in.cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
    let body = me.json();
    assert_eq!(body["signIn"], "citizen");
    assert_eq!(body["claims"]["sub"], "citizen-a");
    assert_eq!(body["claims"]["name"], "Name of citizen-a");
    assert!(!me.body.to_ascii_lowercase().contains("token"));
    assert!(!me.marked());

    let allowed = harness
        .check("GET", "/api/registry/records", Some(&signed_in.cookie))
        .await;
    assert_eq!(allowed.status, StatusCode::OK);
    assert_eq!(audience_of(&bearer(&allowed)), PERSON_AUDIENCE);
    assert!(!allowed.marked());
}

#[tokio::test]
async fn the_authorization_request_carries_the_flow_the_service_promises() {
    let harness = Harness::start().await;
    let start = harness.start_sign_in("/apply/").await;
    assert_eq!(start.status, StatusCode::FOUND);
    let location = url::Url::parse(start.location()).expect("location");
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], CITIZEN_CLIENT);
    assert_eq!(
        query["redirect_uri"],
        format!("{}/session/callback", harness.public)
    );
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["resource"], PERSON_AUDIENCE);
    assert_eq!(query["scope"], "openid registry:read");
    assert!(!query.contains_key("prompt"));
    let flow = start.set_cookie(FLOW_COOKIE).expect("flow cookie");
    for attribute in ["HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=600"] {
        assert!(flow.contains(attribute), "{attribute}");
    }
}

#[tokio::test]
async fn a_staff_member_signs_in_in_two_hops_and_each_route_gets_its_own_audience() {
    let harness = Harness::start().await;
    let staff = harness.sign_in("/staff/queue", "staff-a").await;
    assert_eq!(staff.hops, 2);
    assert_eq!(harness.issuer.authorize_calls(), 2);

    let registry = harness
        .check("GET", "/api/registry/records", Some(&staff.cookie))
        .await;
    assert_eq!(audience_of(&bearer(&registry)), PERSON_AUDIENCE);
    let casework = harness
        .check("GET", "/api/casework/cases", Some(&staff.cookie))
        .await;
    assert_eq!(audience_of(&bearer(&casework)), CASEWORK_AUDIENCE);

    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    let refused = harness
        .check("GET", "/api/casework/cases", Some(&citizen.cookie))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(refused.marked());
}

fn move_documents_to_their_own_audience(document: String) -> String {
    let edited = document.replace(
        "prefix: /api/documents/\n    audience: person",
        &format!("prefix: /api/documents/\n    audience: {DOCUMENTS_AUDIENCE}"),
    );
    assert_ne!(edited, document, "the documents module line changed");
    edited
}

#[tokio::test]
async fn moving_one_module_to_its_own_audience_adds_a_hop_and_changes_nothing_else() {
    let harness = Harness::start_with(Options {
        edit: Box::new(move_documents_to_their_own_audience),
        ..Options::default()
    })
    .await;
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    let staff = harness.sign_in("/staff/", "staff-a").await;
    assert_eq!(citizen.hops, 2);
    assert_eq!(staff.hops, 3);

    let documents = harness
        .check("GET", "/api/documents/files", Some(&citizen.cookie))
        .await;
    assert_eq!(documents.status, StatusCode::OK);
    assert_eq!(audience_of(&bearer(&documents)), DOCUMENTS_AUDIENCE);
    let registry = harness
        .check("GET", "/api/registry/records", Some(&citizen.cookie))
        .await;
    assert_eq!(audience_of(&bearer(&registry)), PERSON_AUDIENCE);
    assert!(registry.header("set-cookie").is_none());
    assert_eq!(
        harness
            .check("GET", "/api/registry/records", None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert!(citizen
        .page
        .set_cookie(SESSION_COOKIE)
        .expect("cookie")
        .contains("HttpOnly"));
}

#[tokio::test]
async fn a_later_hop_naming_another_subject_opens_no_session_and_revokes_the_first_token() {
    let harness = Harness::start().await;
    let start = harness.start_sign_in("/staff/").await;
    let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
    let callback = harness.authorize_as(start.location(), "staff-a").await;
    let second = harness.callback(&callback, Some(&flow)).await;
    assert_eq!(second.status, StatusCode::FOUND);
    let flow = second.cookie_pair(FLOW_COOKIE).expect("next flow");
    let callback = harness
        .authorize_as(second.location(), "someone-else")
        .await;
    let refused = harness.callback(&callback, Some(&flow)).await;

    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.set_cookie(SESSION_COOKIE).is_none());
    assert!(refused.marked());
    harness.issuer.wait_live_families(0).await;
    assert!(harness.issuer.revoke_calls() >= 2);
    let flow_cleared = refused.set_cookie(FLOW_COOKIE).expect("flow cleared");
    assert!(flow_cleared.contains("Max-Age=0"));
    assert!(refused.body.contains("/session/sign-in?return=%2Fstaff%2F"));
}

#[tokio::test]
async fn every_callback_refusal_consumes_the_flow() {
    let harness = Harness::start().await;

    // A replayed callback.
    let start = harness.start_sign_in("/apply/").await;
    let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
    let callback = harness.authorize_as(start.location(), "citizen-a").await;
    assert_eq!(
        harness.callback(&callback, Some(&flow)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        harness.callback(&callback, Some(&flow)).await.status,
        StatusCode::BAD_REQUEST
    );

    type Tamper = Box<dyn Fn(&url::Url) -> url::Url>;
    let tampered: [(&str, Tamper); 5] = [
        (
            "wrong state",
            Box::new(|url| replace(url, "state", Some("wrong"))),
        ),
        (
            "wrong iss",
            Box::new(|url| replace(url, "iss", Some("http://other.example"))),
        ),
        ("missing iss", Box::new(|url| replace(url, "iss", None))),
        (
            "an error",
            Box::new(|url| replace(url, "error", Some("access_denied"))),
        ),
        ("no code", Box::new(|url| replace(url, "code", None))),
    ];
    for (name, tamper) in tampered {
        let start = harness.start_sign_in("/apply/").await;
        let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
        let callback = harness.authorize_as(start.location(), "citizen-a").await;
        let altered = tamper(&url::Url::parse(&callback).expect("callback"));
        let refused = harness.callback(altered.as_str(), Some(&flow)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{name}");
        assert!(refused.set_cookie(SESSION_COOKIE).is_none(), "{name}");
        assert!(refused.marked(), "{name}");
        // The genuine callback no longer works: the flow was consumed.
        let again = harness.callback(&callback, Some(&flow)).await;
        assert_eq!(again.status, StatusCode::BAD_REQUEST, "{name}");
    }

    // A token answer without a refresh token cannot hold a session.
    harness.issuer.omit_refresh_tokens(true);
    let refused = harness.sign_in_attempt("/apply/", "citizen-a").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.set_cookie(SESSION_COOKIE).is_none());
    harness.issuer.omit_refresh_tokens(false);
}

fn replace(url: &url::Url, name: &str, value: Option<&str>) -> url::Url {
    let mut result = url.clone();
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    result.set_query(None);
    {
        let mut pairs = result.query_pairs_mut();
        for (key, existing) in kept {
            pairs.append_pair(&key, &existing);
        }
        if let Some(value) = value {
            pairs.append_pair(name, value);
        }
    }
    result
}

#[tokio::test]
async fn sign_out_revokes_every_token_and_ends_the_session() {
    let harness = Harness::start().await;
    let staff = harness.sign_in("/staff/", "staff-a").await;
    let issued = harness.issuer.issued_refresh_tokens();
    assert_eq!(issued.len(), 2);
    let copy = staff.cookie.clone();

    let out = harness
        .sign_out(Some(&staff.cookie), &[("origin", harness.public.as_str())])
        .await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    let location = url::Url::parse(out.location()).expect("location");
    assert!(location
        .as_str()
        .starts_with(&format!("{}/logout", harness.issuer.origin())));
    let names: Vec<String> = location
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    assert!(names.contains(&"client_id".to_owned()));
    assert!(names.contains(&"post_logout_redirect_uri".to_owned()));
    assert!(!names.contains(&"id_token_hint".to_owned()));
    assert!(out
        .set_cookie(SESSION_COOKIE)
        .expect("cleared")
        .contains("Max-Age=0"));

    harness.issuer.wait_live_families(0).await;
    for (client, token) in issued {
        assert_eq!(client, STAFF_CLIENT);
        assert_eq!(
            harness.issuer.try_refresh(&client, &token).await,
            StatusCode::BAD_REQUEST
        );
    }
    let after = harness
        .check("GET", "/api/registry/records", Some(&copy))
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert!(after.marked());
    assert_eq!(
        harness.get("/session/me", Some(&copy)).await.status,
        StatusCode::UNAUTHORIZED
    );
    harness.get("/session/signed-out", None).await;
}

#[tokio::test]
async fn sign_out_without_a_session_clears_the_cookie_and_lands_on_the_signed_out_page() {
    let harness = Harness::start().await;
    let out = harness.sign_out(None, &[("registry-client", "page")]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert_eq!(out.location(), "/session/signed-out");
    let page = harness.get("/session/signed-out", None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains("<script"));
    assert!(!page.marked());
}

#[tokio::test]
async fn sign_out_from_a_foreign_origin_is_refused_and_the_session_survives() {
    let harness = Harness::start().await;
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    for headers in [
        vec![("origin", "https://evil.example")],
        vec![
            ("registry-client", "page"),
            ("origin", "https://evil.example"),
        ],
        vec![
            ("registry-client", "page"),
            ("sec-fetch-site", "cross-site"),
        ],
        vec![
            ("origin", harness.public.as_str()),
            ("sec-fetch-site", "same-site"),
        ],
        vec![],
    ] {
        let refused = harness.sign_out(Some(&citizen.cookie), &headers).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{headers:?}");
        assert_eq!(refused.json()["code"], "session.refused");
        assert!(refused.marked());
    }
    assert_eq!(
        harness
            .get("/session/me", Some(&citizen.cookie))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(harness.issuer.live_families(), 1);
}

#[tokio::test]
async fn the_return_path_grammar_refuses_everything_but_a_page_path() {
    let harness = Harness::start().await;
    for refused in [
        "https://evil.example/apply/",
        "//evil.example/apply/",
        "/api/registry/records",
        "/elsewhere/",
        "/apply/../staff/",
        "/apply/./x",
        "/apply//x",
        "/apply/%2Fx",
        "/apply/%5Cx",
        "/apply/%2e%2e/x",
        "/apply\\x",
        "apply/",
        "",
    ] {
        let page = harness.start_sign_in(refused).await;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{refused:?}");
        assert!(page.marked(), "{refused:?}");
    }
    let long = format!("/apply/{}", "a".repeat(2048));
    assert_eq!(
        harness.start_sign_in(&long).await.status,
        StatusCode::BAD_REQUEST
    );
    for query in [
        "",
        "?other=%2Fapply%2F",
        "?return=%2Fapply%2F&return=%2Fapply%2F",
        "?return=%2Fapply%2F&extra=1",
    ] {
        let page = harness.get(&format!("/session/sign-in{query}"), None).await;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{query:?}");
    }
    assert_eq!(harness.issuer.authorize_calls(), 0);
    // A page path with a query is accepted: the check sends it back that way.
    assert_eq!(
        harness.start_sign_in("/apply/form?step=2").await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn the_two_listeners_serve_only_their_own_routes() {
    let harness = Harness::start().await;
    let on_public = harness.get("/check/api/registry/records", None).await;
    assert_eq!(on_public.status, StatusCode::NOT_FOUND);
    assert!(on_public.marked());
    assert_eq!(
        on_public.header("content-type"),
        Some("application/problem+json")
    );
    let unknown = harness.get("/nowhere", None).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert!(unknown.marked());
    assert_eq!(unknown.header("cache-control"), Some("no-store"));

    let on_check = harness
        .http
        .get(format!("{}/session/me", harness.check))
        .send()
        .await
        .expect("response");
    assert_ne!(on_check.status(), reqwest::StatusCode::OK);
    let page = support::page(on_check).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
}

/// Several renewals in a row, with the real token client against an issuer
/// that rotates every refresh token and revokes the family of a reused one:
/// each renewal presents the token the last one returned, so no family dies.
#[tokio::test]
async fn five_parallel_checks_in_the_renewal_window_make_one_refresh_and_later_renewals_work() {
    let harness = Harness::start_with(Options {
        extra_document: "session:\n  renewBeforeSeconds: 10\n".to_owned(),
        ..Options::default()
    })
    .await;
    // A 4 second token is renewed with 2 seconds left, half its lifetime.
    harness.issuer.set_access_lifetime(4);
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    tokio::time::sleep(Duration::from_millis(2100)).await;

    let one = || harness.check("GET", "/api/registry/records", Some(&citizen.cookie));
    let (a, b, c, d, e) = tokio::join!(one(), one(), one(), one(), one());
    let replies = [a, b, c, d, e];
    assert!(replies.iter().all(|reply| reply.status == StatusCode::OK));
    // One check renews. The others, whose token is still valid, use it at once.
    assert_eq!(harness.issuer.refresh_calls(), 1);
    let tokens: std::collections::HashSet<String> = replies.iter().map(bearer).collect();
    assert!(tokens.len() <= 2);

    for round in 2..=4 {
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let reply = one().await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(harness.issuer.refresh_calls(), round);
    }
    assert_eq!(harness.issuer.live_families(), 1);
}

#[tokio::test]
async fn the_browsers_cookie_header_stays_small() {
    let harness = Harness::start().await;
    let staff = harness.sign_in("/staff/", "staff-a").await;
    let another = harness.start_sign_in("/staff/").await;
    let flow = another.cookie_pair(FLOW_COOKIE).expect("a flow cookie");
    // Both cookies travel on every call, names included.
    let header = format!("{}; {flow}", staff.cookie);
    assert!(header.len() <= 130, "{} bytes", header.len());
}

fn long_base64url_run(text: &str) -> bool {
    let mut run = 0;
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
            run += 1;
            if run >= 40 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[tokio::test]
async fn no_public_body_carries_a_token() {
    let harness = Harness::start().await;
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    let mut bodies = vec![citizen.page.body.clone()];
    bodies.push(harness.get("/session/me", Some(&citizen.cookie)).await.body);
    bodies.push(harness.get("/session/me", None).await.body);
    bodies.push(harness.get("/session/signed-out", None).await.body);
    bodies.push(harness.get("/nowhere", None).await.body);
    bodies.push(harness.start_sign_in("/nowhere").await.body);
    bodies.push(
        harness
            .sign_out(Some(&citizen.cookie), &[("origin", "https://evil.example")])
            .await
            .body,
    );
    let start = harness.start_sign_in("/apply/").await;
    let flow = start.cookie_pair(FLOW_COOKIE).expect("flow");
    let callback = harness.authorize_as(start.location(), "citizen-a").await;
    let altered = replace(
        &url::Url::parse(&callback).expect("url"),
        "state",
        Some("wrong"),
    );
    bodies.push(harness.callback(altered.as_str(), Some(&flow)).await.body);
    for body in bodies {
        assert!(!body.contains("eyJ"), "{body}");
        assert!(!long_base64url_run(&body), "{body}");
    }
}

#[tokio::test]
async fn an_audit_write_failure_at_sign_in_leaves_no_session() {
    let sink = AuditSink::default();
    sink.fail_after(0);
    let harness = Harness::start_with(Options {
        audit_sink: Some(sink.clone()),
        ..Options::default()
    })
    .await;
    let refused = harness.sign_in_attempt("/apply/", "citizen-a").await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(refused.set_cookie(SESSION_COOKIE).is_none());
    harness.issuer.wait_live_families(0).await;
}

#[tokio::test]
async fn the_audit_names_pseudonyms_actions_and_outcomes_never_a_subject() {
    let sink = AuditSink::default();
    let harness = Harness::start_with(Options {
        audit_sink: Some(sink.clone()),
        ..Options::default()
    })
    .await;
    let citizen = harness.sign_in("/apply/", "citizen-subject-canary").await;
    // A check is never audited.
    harness
        .check("GET", "/api/registry/records", Some(&citizen.cookie))
        .await;
    harness
        .sign_out(
            Some(&citizen.cookie),
            &[("origin", harness.public.as_str())],
        )
        .await;
    let text = sink.text();
    assert!(!text.contains("citizen-subject-canary"));
    assert!(text.contains("\"action\":\"sign-in\""));
    assert!(text.contains("\"action\":\"sign-out\""));
    assert!(text.contains("principalPseudonym"));
    assert_eq!(text.matches("\"phase\":\"request\"").count(), 2, "{text}");
}

#[tokio::test]
async fn a_refused_renewal_ends_the_session_and_is_audited() {
    let sink = AuditSink::default();
    let harness = Harness::start_with(Options {
        audit_sink: Some(sink.clone()),
        ..Options::default()
    })
    .await;
    // A 4 second token is due for renewal at half its lifetime.
    harness.issuer.set_access_lifetime(4);
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    harness.issuer.set_access_lifetime(600);
    // The refresh token is spent elsewhere, so the issuer revokes the family.
    let (client, token) = harness.issuer.issued_refresh_tokens().remove(0);
    assert_eq!(
        harness.issuer.try_refresh(&client, &token).await,
        StatusCode::OK
    );
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let reply = harness
        .check("GET", "/api/registry/records", Some(&citizen.cookie))
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(sink.text().contains("session-ended"));
}

#[tokio::test]
async fn a_module_route_never_answers_a_redirect() {
    let harness = Harness::start().await;
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    for cookie in [None, Some(citizen.cookie.as_str())] {
        for path in [
            "/api/registry/records",
            "/api/casework/cases",
            "/api/documents/files",
        ] {
            for method in ["GET", "POST", "PUT", "DELETE"] {
                let reply = harness.check(method, path, cookie).await;
                assert!(
                    !reply.status.is_redirection(),
                    "{method} {path}: {}",
                    reply.status
                );
                if reply.status != StatusCode::OK {
                    assert!(reply.marked());
                }
            }
        }
    }
    // A page without a session is the one place a redirect is right.
    let page = harness.check("GET", "/apply/", None).await;
    assert_eq!(page.status, StatusCode::FOUND);
    assert!(page.marked());
}

#[tokio::test]
async fn the_sign_in_rate_limit_throttles_the_start() {
    let harness = Harness::start_with(Options {
        extra_document: "rateLimits:\n  globalSignIn:\n    requestsPerMinute: 1\n    burst: 1\n"
            .to_owned(),
        ..Options::default()
    })
    .await;
    assert_eq!(
        harness.start_sign_in("/apply/").await.status,
        StatusCode::FOUND
    );
    let throttled = harness.start_sign_in("/apply/").await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.header("retry-after").is_some());
    assert!(throttled.marked());
}

#[tokio::test]
async fn the_per_person_limit_applies_to_sign_in() {
    let harness = Harness::start_with(Options {
        extra_document: "rateLimits:\n  perPerson:\n    requestsPerMinute: 1\n    burst: 1\n"
            .to_owned(),
        ..Options::default()
    })
    .await;
    harness.sign_in("/apply/", "citizen-a").await;
    let throttled = harness.sign_in_attempt("/apply/", "citizen-a").await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.set_cookie(SESSION_COOKIE).is_none());
    // Another person is not affected.
    harness.sign_in("/apply/", "citizen-b").await;
}

#[tokio::test]
async fn every_public_path_the_gateway_routes_is_served_and_its_headers_agree() {
    let harness = Harness::start().await;
    for path in registry_session::gateway::PUBLIC_PATHS {
        let page = harness.get(path, None).await;
        assert_ne!(page.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(
        registry_session::gateway::AUTHORIZATION_HEADER,
        axum::http::header::AUTHORIZATION.as_str()
    );
    let citizen = harness.sign_in("/apply/", "citizen-a").await;
    let allowed = harness
        .check("GET", "/api/registry/records", Some(&citizen.cookie))
        .await;
    assert!(allowed
        .header(registry_session::gateway::AUTHORIZATION_HEADER)
        .is_some());
}

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
async fn no_log_line_carries_a_cookie_a_token_a_code_a_state_or_a_secret() {
    captured_logs();
    let harness = Harness::start().await;
    // A complete sign-in, keeping the callback so its code and state are known.
    let start = harness.start_sign_in("/apply/").await;
    let flow = start
        .cookie_pair(support::FLOW_COOKIE)
        .expect("flow cookie");
    let callback = harness.authorize_as(start.location(), "citizen-a").await;
    let query: std::collections::HashMap<String, String> = url::Url::parse(&callback)
        .expect("callback url")
        .query_pairs()
        .into_owned()
        .collect();
    let done = harness.callback(&callback, Some(&flow)).await;
    assert_eq!(done.status, StatusCode::OK);
    let cookie = done.cookie_pair(SESSION_COOKIE).expect("session cookie");
    let session_value = cookie.split_once('=').expect("pair").1.to_owned();
    let allowed = harness
        .check("GET", "/api/registry/records", Some(&cookie))
        .await;
    let access = bearer(&allowed);
    // Refusals and a replayed callback exercise the warning paths.
    harness.callback(&callback, Some(&flow)).await;
    harness
        .check("GET", "/api/casework/tasks", Some(&cookie))
        .await;
    harness.get("/session/me", Some(&cookie)).await;
    harness
        .sign_out(Some(&cookie), &[("origin", &harness.public)])
        .await;

    let text = captured_logs();
    assert!(!text.is_empty(), "the service logs something");
    let mut secrets = vec![
        session_value,
        access,
        harness.citizen_secret.clone(),
        harness.staff_secret.clone(),
    ];
    secrets.extend(query.get("code").cloned());
    secrets.extend(query.get("state").cloned());
    secrets.extend(
        harness
            .issuer
            .issued_refresh_tokens()
            .into_iter()
            .map(|(token, _)| token),
    );
    secrets.extend(
        harness
            .issuer
            .authorize_log()
            .iter()
            .filter_map(|request| request.get("state").cloned()),
    );
    for secret in secrets {
        assert!(!secret.is_empty());
        assert!(!text.contains(&secret), "a log line carries a secret value");
    }
}

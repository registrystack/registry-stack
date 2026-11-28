// SPDX-License-Identifier: Apache-2.0

//! Every refusal of a facade caller, end to end through the built `adapter`
//! binary over a real journal: the answer is frozen against a checked-in
//! golden file (status, `content-type`, `www-authenticate`, `retry-after`,
//! `cache-control` and the body with its correlation identifier removed), the
//! refusal counter on the operator-private metrics listener rises by one under
//! the check that refused, and the log carries one value-free line naming that
//! check.
//!
//! `ADAPTER_WRITE_GOLDEN=1` rewrites the golden file from the running binary.
//! Without it the answers are compared to the file. Needs
//! `ADAPTER_TEST_DATABASE_URL`; without it every test fails on the spot.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, copy_govstack_project, fixture, Served, STDERR_WAIT};

const GET_PATH: &str = "/govstack/registries/v1/collections/people/records/EeBJ3Sn9uLg";
const LIST_PATH: &str = "/govstack/registries/v1/collections/people/records";
const LOOKUP_PATH: &str = "/govstack/registries/v1/collections/people/lookup";
const COUNTER: &str = "adapter_request_refusals_total";
const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/facade_refusals.json"
);

/// A second access profile for the copied project: a caller holding
/// `records.write` is admitted to retrieve and to nothing else.
const WRITER_PROFILE: &str = "  - id: records-writer\n    scopes: [records.write]\n    operations: [retrieve]\n    recordTypes: [people]\n";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind a probe port")
        .local_addr()
        .expect("the probe port")
        .port()
}

fn scrape(port: u16) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect the metrics port");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read");
    raw.split_once("\r\n\r\n")
        .expect("a header block")
        .1
        .to_owned()
}

/// The refusal counter as `check -> count`.
fn refusals(port: u16) -> BTreeMap<String, u64> {
    scrape(port)
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix(COUNTER)?.strip_prefix("{check=\"")?;
            let (check, count) = rest.split_once("\"} ")?;
            Some((check.to_owned(), count.parse().expect("a counter value")))
        })
        .collect()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// The answer as the golden file holds it. The correlation identifiers differ
/// per request, so they are replaced by a marker.
fn frozen(status: u16, head: &str, body: &Value) -> Value {
    let mut body = body.clone();
    if let Some(object) = body.as_object_mut() {
        for member in ["traceId", "requestId"] {
            if object.contains_key(member) {
                object.insert(member.to_owned(), json!("<per-request>"));
            }
        }
    }
    json!({
        "status": status,
        "content-type": header(head, "content-type"),
        "www-authenticate": header(head, "www-authenticate"),
        "retry-after": header(head, "retry-after"),
        "cache-control": header(head, "cache-control"),
        "body": body,
    })
}

/// The `request refused` lines the binary wrote, as their `failed_check`
/// values, in order.
fn refused_lines(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .filter(|event| event["fields"]["message"] == "request refused")
        .map(|event| {
            assert_eq!(event["fields"]["decision"], "refused");
            event["fields"]["failed_check"]
                .as_str()
                .expect("a failed check")
                .to_owned()
        })
        .collect()
}

fn page(page: u64) -> Response {
    let document = fixture("search-page");
    let mut body = document["entries"][0]["upstream"][0]["response"]["body"].clone();
    body["pager"]["page"] = json!(page);
    body["pager"]["pageCount"] = json!(9);
    Response::json(200, &body.to_string())
}

struct Case {
    name: &'static str,
    status: u16,
    head: String,
    body: Value,
    check: &'static str,
}

#[tokio::test]
async fn every_refusal_keeps_its_answer_and_is_counted_and_logged_under_its_check() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page(1)]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_govstack_project(directory.path());
    let project = directory.path().join("project.yaml");
    let mut text = std::fs::read_to_string(&project).expect("the project is readable");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(WRITER_PROFILE);
    std::fs::write(&project, text).expect("write the project");
    let metrics_port = free_port();
    let served =
        Served::start_with_metrics(&upstream.url(""), directory.path(), metrics_port).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the test clock follows the epoch")
        .as_secs();
    let reader = served.token("records.read");
    let first = served.get(&format!("{LIST_PATH}?pageSize=5"), Some(&reader));
    assert_eq!(first.0, 200, "{}", first.2);
    let cursor = first.2["pageInfo"]["nextCursor"]
        .as_str()
        .expect("a cursor")
        .to_owned();
    let tokens: Vec<(&str, String)> = vec![
        ("wrong-audience", served.token_with("subject", "records.read", json!({"aud": "another-service"}))),
        ("expired", served.token_with("subject", "records.read", json!({"exp": now.saturating_sub(3_600)}))),
        ("unlisted-client", served.token_with("subject", "records.read", json!({"client_id": "stranger"}))),
        (
            "exchanged",
            served.token_with(
                "subject",
                "records.read",
                json!({registry_platform_oidc::ASSERTION_ISSUER_CLAIM: "https://other.example.invalid"}),
            ),
        ),
        ("subject-too-long", served.token_for(&"s".repeat(257), "records.read")),
        ("scope-not-held", served.token("other.scope")),
        ("operation-not-named", served.token("records.write")),
        (
            "cursor-of-another-client",
            served.token_with(
                served_harness::SUBJECT,
                "records.read",
                json!({"client_id": served_harness::SECOND_CLIENT}),
            ),
        ),
    ];
    let token = |name: &str| {
        tokens
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| value.as_str())
            .expect("a prepared token")
    };

    let mut cases: Vec<Case> = Vec::new();
    let mut run = |name: &'static str, check: &'static str, answer: (u16, String, Value)| {
        cases.push(Case {
            name,
            status: answer.0,
            head: answer.1,
            body: answer.2,
            check,
        });
    };
    run(
        "no-authorization",
        "credential-missing",
        served.get(GET_PATH, None),
    );
    run(
        "basic-scheme",
        "credential-missing",
        served.request(
            "GET",
            GET_PATH,
            None,
            &[("Authorization", "Basic YWJjOmRlZg==")],
            b"",
        ),
    );
    run(
        "bearer-without-token",
        "credential-malformed",
        served.request("GET", GET_PATH, None, &[("Authorization", "Bearer")], b""),
    );
    run(
        "not-a-compact-token",
        "credential-malformed",
        served.get(GET_PATH, Some("not-a-token")),
    );
    run(
        "unknown-signer",
        "token-signature",
        served.get(GET_PATH, Some(&Served::forged_token())),
    );
    run(
        "wrong-audience",
        "token-audience",
        served.get(GET_PATH, Some(token("wrong-audience"))),
    );
    run(
        "expired",
        "token-time",
        served.get(GET_PATH, Some(token("expired"))),
    );
    run(
        "unlisted-client",
        "token-client",
        served.get(GET_PATH, Some(token("unlisted-client"))),
    );
    run(
        "exchanged",
        "token-assertion-issuer",
        served.get(GET_PATH, Some(token("exchanged"))),
    );
    run(
        "subject-too-long",
        "token-claims",
        served.get(GET_PATH, Some(token("subject-too-long"))),
    );
    run(
        "scope-not-held",
        "scope",
        served.get(GET_PATH, Some(token("scope-not-held"))),
    );
    run(
        "operation-not-named",
        "operation",
        served.post(LOOKUP_PATH, Some(token("operation-not-named")), &json!({})),
    );
    run(
        "cursor-of-another-client",
        "ownership",
        served.get(
            &format!("{LIST_PATH}?cursor={cursor}"),
            Some(token("cursor-of-another-client")),
        ),
    );

    let frozen_answers: Value = Value::Object(
        cases
            .iter()
            .map(|case| {
                (
                    case.name.to_owned(),
                    frozen(case.status, &case.head, &case.body),
                )
            })
            .collect(),
    );
    if std::env::var_os("ADAPTER_WRITE_GOLDEN").is_some() {
        std::fs::create_dir_all(std::path::Path::new(GOLDEN).parent().expect("a directory"))
            .expect("create the golden directory");
        std::fs::write(
            GOLDEN,
            serde_json::to_string_pretty(&frozen_answers).expect("serialize the golden") + "\n",
        )
        .expect("write the golden file");
    }
    let golden: Value = serde_json::from_str(
        &std::fs::read_to_string(GOLDEN).expect("the golden file is checked in"),
    )
    .expect("the golden file is JSON");
    assert_eq!(frozen_answers, golden, "a refusal answer changed");

    let mut expected: BTreeMap<String, u64> = BTreeMap::new();
    for case in &cases {
        *expected.entry(case.check.to_owned()).or_default() += 1;
    }
    let counted = refusals(metrics_port);
    for (check, count) in &expected {
        assert_eq!(
            counted.get(check),
            Some(count),
            "the counter for {check}: {counted:?}"
        );
    }
    assert_eq!(
        counted.values().sum::<u64>(),
        expected.values().sum::<u64>(),
        "no other check was counted: {counted:?}"
    );
    assert_eq!(counted.len(), 45, "every check is declared at zero");

    let stderr = served.wait_for_stderr("\"request refused\"", STDERR_WAIT);
    std::thread::sleep(Duration::from_millis(300));
    let stderr = served.stderr_text().max(stderr);
    let mut logged = refused_lines(&stderr);
    logged.sort();
    let mut wanted: Vec<String> = cases.iter().map(|case| case.check.to_owned()).collect();
    wanted.sort();
    assert_eq!(logged, wanted, "one value-free line per refusal");
    for secret in tokens.iter().map(|(_, value)| value.as_str()).chain([
        reader.as_str(),
        "stranger",
        cursor.as_str(),
    ]) {
        assert!(!stderr.contains(secret), "a caller value reached the log");
    }
    let _ = capture;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_development_body_names_the_failed_check_and_production_does_not() {
    let upstream = UpstreamDouble::start();
    let production = Served::start(&upstream.url("")).await;
    let development = Served::start_development(&upstream.url("")).await;
    let (status, _, body) = production.get("/v1/records/person/EeBJ3Sn9uLg", None);
    assert_eq!(status, 401);
    assert!(body.get("failedCheck").is_none(), "{body}");
    let (status, _, body) = development.get("/v1/records/person/EeBJ3Sn9uLg", None);
    assert_eq!(status, 401);
    assert_eq!(body["failedCheck"], "credential-missing", "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_token_is_admitted_in_both_postures() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![
        Response::json(status, &body),
        Response::json(status, &body),
    ]);
    let key = registry_platform_testing::access_token_test_key(jsonwebtoken::Algorithm::ES256);
    let production = Served::start_in_posture_with_key(&upstream.url(""), None, key.clone()).await;
    let development =
        Served::start_in_posture_with_key(&upstream.url(""), Some("development"), key).await;
    let token = production.token("records.read");
    let path = "/v1/records/person/EeBJ3Sn9uLg";
    assert_eq!(production.get(path, Some(&token)).0, 200);
    assert_eq!(development.get(path, Some(&token)).0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cross_signed_token_names_the_signature_check() {
    let upstream = UpstreamDouble::start();
    let partner = registry_platform_testing::access_token_test_key(jsonwebtoken::Algorithm::ES256);
    let served = Served::start_with_partner(&upstream.url(""), &partner).await;
    let token = served.token_with_key("subject", "records.read", json!({}), &partner);
    assert_development_refuses(&served, &token, "token-signature");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unconfigured_issuer_names_the_issuer_check() {
    let upstream = UpstreamDouble::start();
    let served = Served::start_development(&upstream.url("")).await;
    let token = served.token_with(
        "subject",
        "records.read",
        json!({"iss":"https://unknown.example.test"}),
    );
    assert_development_refuses(&served, &token, "token-issuer");
}

fn assert_development_refuses(served: &Served, token: &str, check: &str) {
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(token));
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["failedCheck"], check, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_served_scope_refusal_logs_the_verifying_issuers_scope_claim() {
    let upstream = UpstreamDouble::start();
    let partner = registry_platform_testing::access_token_test_key(jsonwebtoken::Algorithm::ES256);
    let served = Served::start_with_partner(&upstream.url(""), &partner).await;
    let token = served.token_with_key(
        "subject",
        "records.read",
        json!({
            "iss":"https://partner.example.test", "client_id":"partner-client", "scp":"other.read"
        }),
        &partner,
    );
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["failedCheck"], "scope", "{body}");
    let log = served.wait_for_stderr("\"request refused\"", STDERR_WAIT);
    let refusal = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["fields"]["message"] == "request refused")
        .expect("refusal log");
    assert_eq!(refusal["fields"]["scope_claim"], "scp", "{refusal}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_journal_qualifies_the_same_subject_at_two_issuers() {
    let upstream = UpstreamDouble::start();
    let partner = registry_platform_testing::access_token_test_key(jsonwebtoken::Algorithm::ES256);
    let single = Served::start_development(&upstream.url("")).await;
    let multiple = Served::start_with_partner(&upstream.url(""), &partner).await;
    let path = "/v1/records/person/EeBJ3Sn9uLg";
    for (served, token) in [
        (&single, single.token_for("subject", "other.read")),
        (&multiple, multiple.token_for("subject", "other.read")),
        (&multiple, multiple.token_with_key("subject", "", json!({
            "iss":"https://partner.example.test", "client_id":"partner-client", "scp":"other.read"
        }), &partner)),
    ] {
        let (status, _, body) = served.get(path, Some(&token));
        assert_eq!(status, 403, "{body}");
    }

    async fn refused_callers(served: &Served) -> Vec<String> {
        let (database, connection) =
            tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
                .await
                .unwrap();
        tokio::spawn(connection);
        database.query(
            "SELECT DISTINCT caller_ref FROM adapter_journal_events WHERE event_kind = 'callRefused'",
            &[],
        ).await.unwrap().iter().map(|row| row.get(0)).collect()
    }

    assert_eq!(refused_callers(&single).await, ["subject"]);
    let references = refused_callers(&multiple).await;
    assert_eq!(references.len(), 2, "{references:?}");
    assert!(
        references
            .iter()
            .all(|reference| reference.starts_with("sha256:")),
        "{references:?}"
    );
}

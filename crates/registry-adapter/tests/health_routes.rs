// SPDX-License-Identifier: Apache-2.0

//! Live HTTP proof for the unauthenticated `/health` and `/ready` probes of
//! the facade listener. Every test uses the real Adapter binary and a real
//! PostgreSQL journal. Absence of the database URL fails; it never turns
//! this boundary into a skipped test.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use registry_platform_httputil::probe::{HEALTH_BODY, HEALTH_PATH, READY_PATH};
use served_harness::upstream::UpstreamDouble;
use served_harness::{copy_example_project, replace_profile_text, Served};

const READY_BODY: &str = r#"{"developmentSettings":[],"posture":"production","status":"ready"}"#;
const NOT_READY_BODY: &str = r#"{"status":"not-ready"}"#;

/// One raw response: status, header lines (the `date` header, which the HTTP
/// server stamps per response, left out) and the body bytes.
#[derive(Debug, PartialEq, Eq)]
struct Raw {
    status: u16,
    headers: Vec<String>,
    body: Vec<u8>,
}

fn raw(served: &Served, method: &str, path: &str, authorization: Option<&str>) -> Raw {
    let mut stream = TcpStream::connect(("127.0.0.1", served.port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(value) = authorization {
        request.push_str(&format!("Authorization: {value}\r\n"));
    }
    if method != "GET" {
        request.push_str("Content-Length: 0\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).expect("write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read");
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a header block");
    let head = String::from_utf8(bytes[..split].to_vec()).expect("utf8 headers");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status code");
    let mut headers: Vec<String> = lines
        .filter(|line| !line.to_ascii_lowercase().starts_with("date:"))
        .map(str::to_owned)
        .collect();
    headers.sort();
    Raw {
        status,
        headers,
        body: bytes[split + 4..].to_vec(),
    }
}

fn header<'a>(response: &'a Raw, name: &str) -> Option<&'a str> {
    response.headers.iter().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn assert_probe(response: &Raw, status: u16, body: &str) {
    assert_eq!(response.status, status, "{response:?}");
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        body,
        "the body is the constant"
    );
    assert_eq!(header(response, "content-type"), Some("application/json"));
    assert!(
        header(response, "x-registry-request-id").is_none(),
        "a probe mints no request id: {response:?}"
    );
}

#[tokio::test]
async fn probes_answer_identically_under_three_projects_with_and_without_authorization() {
    let upstream = UpstreamDouble::start();
    let second = tempfile::tempdir().expect("a copied Adapter project");
    copy_example_project(second.path());
    replace_profile_text(
        second.path(),
        "    path: /v1/records/{type}\n",
        "    path: /v9/records/{type}\n",
    );
    let projects = [
        Served::start(&upstream.url("")).await,
        Served::start_with_project(&upstream.url(""), &Served::govstack_project()).await,
        Served::start_with_project(&upstream.url(""), second.path()).await,
    ];

    let mut seen: Vec<Vec<Raw>> = Vec::new();
    for served in &projects {
        let token = format!("Bearer {}", served.token(""));
        let mut answers = Vec::new();
        for path in [HEALTH_PATH, READY_PATH] {
            for authorization in [None, Some("Bearer not-a-token"), Some(token.as_str())] {
                answers.push(raw(served, "GET", path, authorization));
            }
        }
        for (position, answer) in answers.iter().enumerate() {
            let expected = if position < 3 {
                HEALTH_BODY
            } else {
                READY_BODY
            };
            assert_probe(answer, 200, expected);
            assert_eq!(header(answer, "registry-posture"), None);
        }
        // The same path answers byte-for-byte alike, whatever the header.
        assert_eq!(answers[0], answers[1]);
        assert_eq!(answers[0], answers[2]);
        assert_eq!(answers[3], answers[4]);
        assert_eq!(answers[3], answers[5]);
        // A method other than GET refuses with no project-specific text.
        let refused = raw(served, "POST", HEALTH_PATH, None);
        assert_eq!(refused.status, 405, "{refused:?}");
        assert_eq!(header(&refused, "allow"), Some("GET"));
        assert!(refused.body.is_empty(), "{refused:?}");
        answers.push(refused);
        seen.push(answers);
    }
    assert_eq!(seen[0], seen[1], "the probes do not vary with the project");
    assert_eq!(seen[0], seen[2], "the probes do not vary with the project");
    assert_eq!(
        upstream.request_count(),
        0,
        "a probe never reaches a source"
    );
}

#[tokio::test]
async fn a_journal_that_is_not_ready_answers_the_constant_503_without_database_text() {
    let upstream = UpstreamDouble::start();
    let served = Served::start(&upstream.url("")).await;
    assert_probe(&raw(&served, "GET", READY_PATH, None), 200, READY_BODY);

    served
        .execute_sql(
            "DELETE FROM adapter_schema_migrations \
             WHERE version = (SELECT max(version) FROM adapter_schema_migrations)",
        )
        .await;
    let drift = raw(&served, "GET", READY_PATH, None);
    assert_probe(&drift, 503, NOT_READY_BODY);

    served
        .execute_sql("DROP TABLE adapter_schema_migrations")
        .await;
    let missing = raw(&served, "GET", READY_PATH, Some("Bearer anything"));
    assert_probe(&missing, 503, NOT_READY_BODY);
    assert_eq!(drift, missing, "the refusal does not carry the cause");
    let text = String::from_utf8_lossy(&missing.body).to_lowercase();
    for fragment in ["relation", "adapter_", "postgres", "sql", "error"] {
        assert!(!text.contains(fragment), "{fragment} leaked: {text}");
    }
    assert_probe(&raw(&served, "GET", HEALTH_PATH, None), 200, HEALTH_BODY);
    assert_eq!(
        upstream.request_count(),
        0,
        "readiness never probes a source"
    );
}

#[tokio::test]
async fn probes_append_no_journal_row() {
    let upstream = UpstreamDouble::start();
    let served = Served::start(&upstream.url("")).await;
    let before = served.journal_kinds().await;
    for _ in 0..3 {
        for path in [HEALTH_PATH, READY_PATH] {
            assert_eq!(raw(&served, "GET", path, None).status, 200);
        }
    }
    served
        .execute_sql("DROP TABLE adapter_schema_migrations")
        .await;
    assert_eq!(raw(&served, "GET", READY_PATH, None).status, 503);
    assert_eq!(
        served.journal_kinds().await,
        before,
        "neither a ready nor a not-ready probe appends an event"
    );
}

#[tokio::test]
async fn a_project_declaring_health_or_ready_refuses_to_start() {
    for record_type in ["health", "ready"] {
        let upstream = UpstreamDouble::start();
        let directory = tempfile::tempdir().expect("a copied Adapter project");
        copy_example_project(directory.path());
        replace_profile_text(
            directory.path(),
            "    path: /v1/records/{type}\n",
            "    path: /{type}\n",
        );
        let project_path = directory.path().join("project.yaml");
        let project =
            std::fs::read_to_string(&project_path).expect("the copied project is readable");
        std::fs::write(&project_path, project.replace("person", record_type))
            .expect("write the colliding project");

        // The workspace check refuses the colliding binding before the facade
        // builds a router, so the probe route is never shadowed.
        let stderr = Served::refusal_with_project(&upstream.url(""), directory.path()).await;
        assert!(
            stderr.contains("the workspace check refused the deployment"),
            "{record_type}: {stderr}"
        );
        assert!(
            stderr.contains("adapter.project.reserved-facade-path"),
            "{record_type}: {stderr}"
        );
        assert_eq!(
            upstream.request_count(),
            0,
            "a refused deployment performs no source I/O"
        );
    }
}

#[tokio::test]
async fn development_readiness_and_startup_name_the_selected_setting() {
    let upstream = UpstreamDouble::start();
    let served = Served::start_development(&upstream.url("")).await;
    let ready = raw(&served, "GET", READY_PATH, None);
    assert_eq!(ready.status, 200);
    assert_eq!(header(&ready, "registry-posture"), Some("development"));
    let body: serde_json::Value = serde_json::from_slice(&ready.body).unwrap();
    assert_eq!(body["posture"], "development");
    assert_eq!(
        body["developmentSettings"],
        serde_json::json!([{
            "code": "platform.posture.insecure-issuer-http", "pointer": "/oidc/allowInsecureHttp"
        }])
    );
    let log = served.stop_and_read_stderr();
    assert!(log.contains("posture declared"), "{log}");
    assert!(
        log.contains("platform.posture.insecure-issuer-http"),
        "{log}"
    );
}

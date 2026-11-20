// SPDX-License-Identifier: Apache-2.0

//! The served facade counts requests, failed source calls, and failed journal
//! writes on the operator-private metrics listener, and on no other socket.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{copy_example_project, Served};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind a probe port")
        .local_addr()
        .expect("the probe port")
        .port()
}

/// One scrape of the metrics listener: the status line and the body.
fn scrape(port: u16) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect the metrics port");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read");
    let (head, body) = raw.split_once("\r\n\r\n").expect("a header block");
    (
        head.lines().next().expect("a status line").to_owned(),
        body.to_owned(),
    )
}

fn has_line(body: &str, line: &str) -> bool {
    body.lines().any(|found| found == line)
}

#[tokio::test]
async fn requests_upstream_failures_and_journal_failures_are_counted() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(500, r#"{"status":"ERROR"}"#)]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    let metrics_port = free_port();
    let served =
        Served::start_with_metrics(&upstream.url(""), directory.path(), metrics_port).await;
    let token = served.token("records.read");

    let (status, _, _) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 502, "a failed source call answers the caller 502");
    let (status, _, _) = served.get("/v1/no-such-path", Some(&token));
    assert_eq!(status, 404);

    let (status_line, body) = scrape(metrics_port);
    assert!(status_line.contains("200"), "{status_line}");
    assert!(has_line(
        &body,
        "adapter_http_requests_total{route=\"/v1/records/{type}/{record_id}\",method=\"GET\",status=\"5xx\"} 1"
    ), "{body}");
    assert!(
        has_line(
            &body,
            "adapter_http_requests_total{route=\"unmatched\",method=\"GET\",status=\"4xx\"} 1"
        ),
        "{body}"
    );
    assert!(
        has_line(
            &body,
            "adapter_upstream_failures_total{class=\"upstream.http\"} 1"
        ),
        "{body}"
    );
    assert!(
        has_line(&body, "adapter_journal_write_failures_total 0"),
        "{body}"
    );
    assert!(
        !body.contains("EeBJ3Sn9uLg") && !body.contains("no-such-path"),
        "no path or identifier becomes a label"
    );

    served
        .execute_sql("ALTER TABLE adapter_journal_events RENAME TO adapter_journal_broken")
        .await;
    let (status, _, _) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(
        status, 500,
        "an exchange whose journal write fails answers 500"
    );
    let (_, body) = scrape(metrics_port);
    assert!(
        body.lines().any(|line| line
            .strip_prefix("adapter_journal_write_failures_total ")
            .is_some_and(|count| count.parse::<u64>().is_ok_and(|count| count >= 1))),
        "{body}"
    );
}

#[tokio::test]
async fn the_facade_listener_never_serves_metrics() {
    let upstream = UpstreamDouble::start();
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    let metrics_port = free_port();
    let served =
        Served::start_with_metrics(&upstream.url(""), directory.path(), metrics_port).await;
    let (status, _, body) = served.get("/metrics", None);
    assert_eq!(status, 404, "{body}");
    assert!(!body.to_string().contains("adapter_http_requests_total"));
}

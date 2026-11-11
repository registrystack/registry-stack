// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

fn token_directory() -> tempfile::TempDir {
    let root = fs::canonicalize(std::env::temp_dir()).unwrap();
    tempfile::tempdir_in(root).unwrap()
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).unwrap();
        assert_ne!(read, 0, "client closed before sending a complete request");
        bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .expect("request carries a content length");
        if bytes.len() >= header_end + 4 + content_length {
            return String::from_utf8(bytes).unwrap();
        }
    }
}

#[test]
fn refresh_posts_start_sweep_once_then_runs_while_more_work_is_true() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for more_work in [true, false] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            requests.push(read_request(&mut stream));
            let body = serde_json::to_string(&json!({
                "moreWork": more_work,
                "processed": 1,
                "published": 1,
                "reused": 0,
                "unavailable": 0,
                "retried": 0,
                "settled": 1,
                "sweepCompleted": !more_work,
                "sweepAcquisitionFailures": 0,
                "futureAggregate": 9,
                "selector": "server-controlled-selector-canary"
            }))
            .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
        requests
    });

    let directory = token_directory();
    let token_file = directory.path().join("refresh.jwt");
    fs::write(&token_file, "refresh-session-token-canary\n").unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            "bregctl".into(),
            "--format".into(),
            "json".into(),
            "external-projection".into(),
            "refresh".into(),
            "--breg-url".into(),
            format!("http://{address}").into(),
            "--plan".into(),
            "licensing-holders".into(),
            "--access-token-file".into(),
            token_file.as_os_str().to_owned(),
            "--start-sweep".into(),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(status, std::process::ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let report: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["command"], "external-projection refresh");
    assert_eq!(report["steps"], 2);
    assert_eq!(report["result"]["moreWork"], false);
    assert_eq!(report["result"]["processed"], 1);
    assert_eq!(report["result"]["sweepCompleted"], true);
    assert!(report["result"].get("futureAggregate").is_none());
    assert!(report["result"].get("selector").is_none());
    assert!(!String::from_utf8_lossy(&stdout).contains("refresh-session-token-canary"));
    assert!(!String::from_utf8_lossy(&stdout).contains("server-controlled-selector-canary"));

    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0].starts_with("POST /v1/external-refresh-plans/licensing-holders/step HTTP/1.1")
    );
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains("authorization: bearer refresh-session-token-canary"));
    assert!(requests[0].ends_with(r#"{"startSweep":true}"#));
    assert!(requests[1].ends_with("{}"));
}

#[test]
fn refresh_failures_never_report_the_access_token() {
    let directory = token_directory();
    let token_file = directory.path().join("refresh.jwt");
    fs::write(&token_file, "refresh-failure-token-canary\n").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            "bregctl".into(),
            "--format".into(),
            "json".into(),
            "external-projection".into(),
            "refresh".into(),
            "--breg-url".into(),
            format!("http://{address}").into(),
            "--plan".into(),
            "licensing-holders".into(),
            "--access-token-file".into(),
            token_file.as_os_str().to_owned(),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_ne!(status, std::process::ExitCode::SUCCESS);
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(!rendered.contains("refresh-failure-token-canary"));
}

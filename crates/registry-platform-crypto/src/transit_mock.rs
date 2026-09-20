// SPDX-License-Identifier: Apache-2.0

//! Scripted Unix-socket Transit provider shared by the Transit test suites.
//!
//! Each reply answers exactly one request in order, so a test pins the whole
//! exchange, the method, path, and JSON body the client must send, and the
//! bytes it must accept back.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

pub(crate) struct MockTransitReply {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) body: Option<Value>,
    pub(crate) status: u16,
    pub(crate) response: Vec<u8>,
    pub(crate) delay: Duration,
}

pub(crate) fn spawn_transit_mock(
    replies: Vec<MockTransitReply>,
) -> (TempDir, PathBuf, JoinHandle<()>) {
    let directory = tempfile::tempdir().expect("temporary Transit directory");
    let socket_path = directory.path().join("transit.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind mock Transit socket");
    let task = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.expect("accept Transit request");
            let mut request = Vec::new();
            let header_end = loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("read Transit request");
                assert_ne!(read, 0, "Transit request ended before its headers");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() <= 128 * 1024, "mock request stayed bounded");
                if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..header_end])
                .expect("Transit request headers are UTF-8");
            let mut lines = headers.lines();
            let request_line = lines.next().expect("request line");
            let mut request_parts = request_line.split_whitespace();
            assert_eq!(request_parts.next(), Some(reply.method));
            assert_eq!(request_parts.next(), Some(reply.path));
            let lower_headers = headers.to_ascii_lowercase();
            assert!(
                lower_headers.contains("x-vault-request: true"),
                "Transit request marks the trusted proxy hop"
            );
            let content_length = lines
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().expect("content length"))
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let mut chunk = [0_u8; 4096];
                let read = stream
                    .read(&mut chunk)
                    .await
                    .expect("read Transit request body");
                assert_ne!(read, 0, "Transit request body ended early");
                request.extend_from_slice(&chunk[..read]);
            }
            let actual_body = &request[header_end..header_end + content_length];
            match reply.body {
                Some(expected) => {
                    let actual: Value =
                        serde_json::from_slice(actual_body).expect("Transit request JSON");
                    assert_eq!(actual, expected);
                }
                None => assert!(actual_body.is_empty()),
            }

            if !reply.delay.is_zero() {
                tokio::time::sleep(reply.delay).await;
            }
            let reason = if reply.status == 200 { "OK" } else { "ERROR" };
            let response_headers = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.status,
                reason,
                reply.response.len()
            );
            let _ = stream.write_all(response_headers.as_bytes()).await;
            let _ = stream.write_all(&reply.response).await;
        }
    });
    (directory, socket_path, task)
}

pub(crate) fn transit_reply(
    method: &'static str,
    path: &'static str,
    body: Option<Value>,
    response: Value,
) -> MockTransitReply {
    MockTransitReply {
        method,
        path,
        body,
        status: 200,
        response: serde_json::to_vec(&response).expect("mock response JSON"),
        delay: Duration::ZERO,
    }
}

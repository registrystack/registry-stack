// SPDX-License-Identifier: Apache-2.0

//! INTERIM outbound send: plain HTTP/1.1 to a numeric-loopback origin only.
//!
//! This stands in for the governed egress path (destination policy, TLS
//! trust, mTLS identity, address screening) until that path lands. It is the
//! only implementation of [`UpstreamSend`] in this crate and it is not a
//! production client: every origin that is not `http` on a numeric loopback
//! address is refused with a fixed, visible text. Replacing it is a one-file
//! change: build the governed implementation per endpoint where
//! [`LoopbackSender::new`] is called and delete this module.
//!
//! The pinning and header rules are the shared ones: the link is pinned to
//! the endpoint origin by [`PinnedOrigin`], exchange headers pass through the
//! endpoint's [`HeaderFilter`], and a redirect is never followed.

use std::net::IpAddr;
use std::time::Instant;

use registry_adapter_core::ErrorClass;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::component::http::header_filter::HeaderFilter;
use crate::component::http::uri::PinnedOrigin;
use crate::upstream::{
    EgressError, OutboundSend, SendFuture, SentReply, UpstreamFailure, UpstreamSend,
};

const NOT_LOOPBACK: &str =
    "the interim sender serves only plain http on a numeric loopback address";
const MAXIMUM_HEAD_BYTES: usize = 16 * 1024;

/// One endpoint's interim loopback send.
pub struct LoopbackSender {
    origin: PinnedOrigin,
    filter: HeaderFilter,
}

impl LoopbackSender {
    #[must_use]
    pub fn new(origin: PinnedOrigin, filter: HeaderFilter) -> Self {
        Self { origin, filter }
    }

    async fn exchange(&self, send: OutboundSend<'_>) -> Result<SentReply, EgressError> {
        let link = self
            .origin
            .pin(send.link)
            .map_err(|_| EgressError::Refused("the link left the endpoint origin"))?;
        let url = link.as_url();
        let loopback = url.scheme() == "http"
            && url
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        if !loopback {
            return Err(EgressError::Refused(NOT_LOOPBACK));
        }
        let headers = self
            .filter
            .outbound(send.exchange_headers.iter().map(|(n, v)| (n, v)))
            .map_err(|_| EgressError::Refused("an exchange header cannot travel upstream"))?;
        let host = url.host_str().unwrap_or_default();
        let port = url.port_or_known_default().unwrap_or(80);

        let mut head = format!(
            "GET {} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n",
            link.target()
        )
        .into_bytes();
        for (name, value) in headers.iter() {
            head.extend_from_slice(name.as_str().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        if let Some(credential) = send.authorization {
            head.extend_from_slice(credential.name().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(credential.value().as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");

        let deadline = Instant::now() + send.attempt;
        let connect = TcpStream::connect((host, port));
        let mut stream = match tokio::time::timeout(send.attempt, connect).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => return Err(failure(ErrorClass::UpstreamConnection)),
            Err(_) => return Err(failure(ErrorClass::UpstreamTimeout)),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let raw = tokio::time::timeout(remaining, async {
            stream.write_all(&head).await.map_err(|_| ReadFault::Io)?;
            stream.flush().await.map_err(|_| ReadFault::Io)?;
            read_bounded(
                &mut stream,
                send.maximum_response_bytes + MAXIMUM_HEAD_BYTES,
            )
            .await
        })
        .await;
        // The credential-bearing head is not kept past the write.
        drop(head);
        let raw = match raw {
            Err(_) => return Err(failure(ErrorClass::UpstreamTimeout)),
            Ok(Err(ReadFault::TooLarge)) => return Err(failure(ErrorClass::UpstreamTooLarge)),
            Ok(Err(ReadFault::Io)) => return Err(failure(ErrorClass::UpstreamConnection)),
            Ok(Ok(raw)) => raw,
        };
        let reply = parse(&raw).ok_or_else(|| failure(ErrorClass::UpstreamMalformed))?;
        if reply.body.len() > send.maximum_response_bytes {
            return Err(failure(ErrorClass::UpstreamTooLarge));
        }
        let body = if reply.body.is_empty() {
            None
        } else {
            serde_json::from_slice::<Value>(&reply.body).ok()
        };
        let (low, high) = send.ok_status_range;
        if (300..400).contains(&reply.status) {
            return Err(EgressError::Upstream(UpstreamFailure {
                class: ErrorClass::UpstreamRedirect,
                status: Some(reply.status),
                body: None,
            }));
        }
        let accepted = (low..=high).contains(&reply.status);
        if !accepted && send.throw_exception_on_failure {
            return Err(EgressError::Upstream(UpstreamFailure {
                class: ErrorClass::UpstreamHttp,
                status: Some(reply.status),
                body,
            }));
        }
        if !reply.body.is_empty() && body.is_none() {
            return Err(failure(ErrorClass::UpstreamMalformed));
        }
        let declared = self
            .filter
            .inbound(reply.headers.iter().map(|(n, v)| (n, v.as_bytes())))
            .map_err(|_| failure(ErrorClass::UpstreamMalformed))?;
        Ok(SentReply {
            status: reply.status,
            body: body.unwrap_or(Value::Null),
            headers: declared
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        })
    }
}

impl UpstreamSend for LoopbackSender {
    fn send<'a>(&'a self, send: OutboundSend<'a>) -> SendFuture<'a> {
        Box::pin(self.exchange(send))
    }
}

fn failure(class: ErrorClass) -> EgressError {
    EgressError::Upstream(UpstreamFailure {
        class,
        status: None,
        body: None,
    })
}

enum ReadFault {
    TooLarge,
    Io,
}

async fn read_bounded(stream: &mut TcpStream, limit: usize) -> Result<Vec<u8>, ReadFault> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk).await.map_err(|_| ReadFault::Io)?;
        if read == 0 {
            return Ok(raw);
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len() > limit {
            return Err(ReadFault::TooLarge);
        }
    }
}

struct RawReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Parse one `Connection: close` HTTP/1.1 reply read to end of stream:
/// status line, headers, then a `content-length`, chunked, or
/// read-to-close body.
fn parse(raw: &[u8]) -> Option<RawReply> {
    let head_end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let find = |wanted: &str| {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.as_str())
    };
    let rest = &raw[head_end + 4..];
    let body = if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        dechunk(rest)?
    } else if let Some(length) = find("content-length") {
        let length: usize = length.parse().ok()?;
        if rest.len() < length {
            return None;
        }
        rest[..length].to_vec()
    } else {
        rest.to_vec()
    };
    Some(RawReply {
        status,
        headers,
        body,
    })
}

fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = rest.windows(2).position(|window| window == b"\r\n")?;
        let size = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        if rest.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_content_length_reply() {
        let reply = parse(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(reply.status, 404);
        assert_eq!(reply.body, b"{}");
    }

    #[test]
    fn parses_a_chunked_reply() {
        let reply =
            parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
                .unwrap();
        assert_eq!(reply.body, b"{}");
    }

    #[test]
    fn refuses_a_truncated_body() {
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}").is_none());
    }
}

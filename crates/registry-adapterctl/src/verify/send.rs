// SPDX-License-Identifier: Apache-2.0

//! The one network seam of `verify --live` (`crates/registry-adapterctl/
//! src/verify`): one plain HTTP/1.1 request over `std::net`, bounded in
//! time and in what it reads, returning only the answer's status.
//!
//! TLS, mTLS, token acquisition, and the graphql component are the
//! engine data path's transports; this seam dials plain HTTP to an
//! address the egress policy already admitted, and the command waits
//! instead of dialing anywhere else. No response body is read: the
//! facade mapping that validates bodies is the engine's. The request
//! head is assembled as bytes, so a non-UTF-8 API-key value crosses to
//! the wire unchanged.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// One rendered probe request. The authorization header value travels
/// as bytes because a static-api-key value need not be UTF-8.
pub(crate) struct WireRequest {
    /// The `Host` header value, from the binding's base URL authority.
    pub host_header: String,
    /// Where to connect: the admitted address and port.
    pub address: SocketAddr,
    /// The request method, upper case.
    pub method: String,
    /// The request target: path and query, origin-relative.
    pub target: String,
    /// The header the credential composes, if any.
    pub authorization: Option<(String, Vec<u8>)>,
    /// The marshalled constant body, if any.
    pub body: Option<Vec<u8>>,
}

/// Why the seam could not produce a status. The text names the failure
/// kind; it never carries a credential value.
pub(crate) struct TransportFailure(pub String);

/// One request and one answer each take at most this long.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The response head the seam reads, bounded: status line and headers,
/// never a body.
const HEAD_LIMIT: usize = 64 * 1024;

/// Send one request, read one response head, and return its status.
pub(crate) fn send_once(request: &WireRequest) -> Result<u16, TransportFailure> {
    let failure = |kind: &str, error: std::io::Error| TransportFailure(format!("{kind}: {error}"));
    let mut stream = TcpStream::connect_timeout(&request.address, TIMEOUT)
        .map_err(|error| failure("connect", error))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|error| failure("set the read timeout", error))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|error| failure("set the write timeout", error))?;

    // The head is bytes throughout: a credential value crosses to the
    // wire unchanged whatever its bytes are.
    let mut head = Vec::new();
    head.extend_from_slice(
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n",
            request.method, request.target, request.host_header
        )
        .as_bytes(),
    );
    if let Some((name, value)) = &request.authorization {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    let body = request.body.as_deref().unwrap_or(&[]);
    if !body.is_empty() {
        head.extend_from_slice(
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            )
            .as_bytes(),
        );
    }
    head.extend_from_slice(b"\r\n");
    stream
        .write_all(&head)
        .map_err(|error| failure("write the request", error))?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .map_err(|error| failure("write the body", error))?;
    }
    stream
        .flush()
        .map_err(|error| failure("flush the request", error))?;

    let mut read = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if read.len() > HEAD_LIMIT {
            return Err(TransportFailure(
                "the response head exceeds the 64 KiB bound".to_owned(),
            ));
        }
        let count = stream
            .read(&mut chunk)
            .map_err(|error| failure("read the response", error))?;
        if count == 0 {
            return Err(TransportFailure(
                "the connection closed before a response head".to_owned(),
            ));
        }
        read.extend_from_slice(&chunk[..count]);
        if let Some(end) = find(&read, b"\r\n\r\n") {
            return status_of(&read[..end]);
        }
    }
}

/// The status of one response head: the first line's second member,
/// after the version.
fn status_of(head: &[u8]) -> Result<u16, TransportFailure> {
    let text = String::from_utf8_lossy(head);
    let line = text.lines().next().unwrap_or_default();
    let mut members = line.split(' ');
    let version = members.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(TransportFailure(format!(
            "the answer's status line is not HTTP: {line}"
        )));
    }
    members
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            TransportFailure(format!(
                "the answer's status line carries no status: {line}"
            ))
        })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

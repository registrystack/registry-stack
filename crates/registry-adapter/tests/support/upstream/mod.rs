// SPDX-License-Identifier: Apache-2.0

//! A loopback HTTP/1.1 double for the upstream authentication kinds
//! (`products/adapter/CONCEPT.md` section 10.2).
//!
//! The double is a real TCP server on `127.0.0.1:0` speaking just enough
//! HTTP/1.1 for the authentication layer: one request per connection,
//! `Connection: close`, a scripted response queue, and a value-complete
//! record of every request it received. The record is deliberately
//! value-complete, credentials included, because the tests' job is to
//! prove the credential traveled exactly where the concept says and
//! nowhere else; nothing outside this directory ever sees a record.
//!
//! [`LoopbackSend`] is the client side: an async `TokenSend` over
//! the same loopback transport. It copies credential bytes straight from
//! the auth layer's zeroizing buffer to the socket and never formats
//! them into an intermediate string, the way the engine's outbound
//! client will.

use http::{HeaderName, HeaderValue};
use registry_adapter::auth::{
    ProtectedText, TokenClientAuthentication, TokenRequest, TokenSend, TokenWire, TransportFailure,
    TOKEN_REQUEST_ACCEPT, TOKEN_REQUEST_CONTENT_TYPE,
};
use registry_platform_httputil::TransportKind;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// One request the double received, headers and body complete.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// The request method.
    pub method: String,
    /// The request target, path and query as sent.
    pub target: String,
    /// The headers as sent, in order.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// One header's value by name, compared without case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body as text, for form members.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One scripted response.
#[derive(Debug, Clone)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The media type, written as the content type.
    pub media_type: &'static str,
    /// The body.
    pub body: String,
}

impl Response {
    /// One `application/json` response.
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            media_type: "application/json",
            body: body.to_owned(),
        }
    }

    /// One token-refusal response carrying an OAuth error member.
    pub fn refused(status: u16, code: &str, description: &str) -> Self {
        Self::json(
            status,
            &format!(r#"{{"error":"{code}","error_description":"{description}"}}"#),
        )
    }
}

/// How the double delivers one otherwise ordinary HTTP response. These
/// faults stay test-only and preserve the response's declared length, so the
/// production client must detect truncation or spend its own deadline.
#[derive(Debug, Clone)]
enum ResponseDelivery {
    Complete,
    CompleteWithHeaders(Vec<(String, String)>),
    ResetAfter(usize),
    Trickle { chunk_bytes: usize, delay: Duration },
}

/// The double: a loopback TCP server with a scripted response queue and
/// a complete request record.
pub struct UpstreamDouble {
    listener: TcpListener,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<(Response, ResponseDelivery)>>>,
    delay_millis: Arc<AtomicU64>,
}

impl UpstreamDouble {
    /// Start the double on an unused loopback port.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the double binds loopback");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::new()));
        let delay_millis = Arc::new(AtomicU64::new(0));
        let double = Self {
            listener: listener
                .try_clone()
                .expect("the listener clones for the accept loop"),
            requests: Arc::clone(&requests),
            responses: Arc::clone(&responses),
            delay_millis: Arc::clone(&delay_millis),
        };
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    continue;
                };
                let requests = Arc::clone(&requests);
                let responses = Arc::clone(&responses);
                let delay_millis = Arc::clone(&delay_millis);
                std::thread::spawn(move || serve(stream, requests, responses, delay_millis));
            }
        });
        double
    }

    /// One absolute URL on the double.
    pub fn url(&self, path: &str) -> String {
        format!(
            "http://{}{path}",
            self.listener.local_addr().expect("the local address")
        )
    }

    /// Script the responses, served in order, one per request.
    pub fn respond_with(&self, responses: Vec<Response>) {
        *self.responses.lock().expect("the response script") = responses
            .into_iter()
            .map(|response| (response, ResponseDelivery::Complete))
            .collect();
    }

    /// Script one complete response with validated extra headers. Framing
    /// headers stay owned by the double, so tests cannot create an ambiguous
    /// response by overriding them.
    pub fn respond_with_headers(&self, response: Response, headers: Vec<(String, String)>) {
        for (name, value) in &headers {
            HeaderName::from_bytes(name.as_bytes()).expect("a valid response header name");
            HeaderValue::from_str(value).expect("a valid response header value");
            assert!(
                ![
                    "connection",
                    "content-length",
                    "content-type",
                    "transfer-encoding"
                ]
                .iter()
                .any(|owned| name.eq_ignore_ascii_case(owned)),
                "the double owns response framing headers"
            );
        }
        *self.responses.lock().expect("the response script") =
            [(response, ResponseDelivery::CompleteWithHeaders(headers))].into();
    }

    /// Send the declared head and `body_bytes` body bytes, then close the
    /// connection before the declared body is complete.
    pub fn respond_with_reset(&self, response: Response, body_bytes: usize) {
        *self.responses.lock().expect("the response script") =
            [(response, ResponseDelivery::ResetAfter(body_bytes))].into();
    }

    /// Send one response body in fixed chunks, pausing after each chunk.
    pub fn respond_with_trickle(&self, response: Response, chunk_bytes: usize, delay: Duration) {
        assert!(chunk_bytes > 0, "a trickle chunk must carry bytes");
        *self.responses.lock().expect("the response script") =
            [(response, ResponseDelivery::Trickle { chunk_bytes, delay })].into();
    }

    /// Hold every answer back by `delay` after the request is recorded.
    pub fn delay_answers(&self, delay: Duration) {
        let millis = u64::try_from(delay.as_millis()).expect("a delay in milliseconds");
        self.delay_millis.store(millis, Ordering::SeqCst);
    }

    /// Every request the double received, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("the request record").clone()
    }

    /// How many requests the double received.
    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("the request record").len()
    }
}

/// Serve one connection: read one request, record it, answer from the
/// script, close. A request the double cannot parse is answered 400, not
/// silently dropped; an exhausted script is answered 500.
fn serve(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<(Response, ResponseDelivery)>>>,
    delay_millis: Arc<AtomicU64>,
) {
    let request = match read_request(&mut stream) {
        Some(request) => request,
        None => {
            write_response(
                &mut stream,
                400,
                "text/plain",
                "the double could not read the request",
                &ResponseDelivery::Complete,
            );
            return;
        }
    };
    requests.lock().expect("the request record").push(request);
    std::thread::sleep(Duration::from_millis(delay_millis.load(Ordering::SeqCst)));
    let (response, delivery) = responses
        .lock()
        .expect("the response script")
        .pop_front()
        .unwrap_or_else(|| {
            (
                Response {
                    status: 500,
                    media_type: "text/plain",
                    body: "the double's response script is exhausted".to_owned(),
                },
                ResponseDelivery::Complete,
            )
        });
    write_response(
        &mut stream,
        response.status,
        response.media_type,
        &response.body,
        &delivery,
    );
}

/// Read one HTTP/1.1 request: head, then `content-length` body bytes.
fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0; 1024];
    let head_end = loop {
        if let Some(position) = find_head_end(&buffer) {
            break position;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let content_length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Some(RecordedRequest {
        method,
        target,
        headers,
        body,
    })
}

/// The offset of the blank line ending a request head, if it arrived.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Write one response and close the connection.
fn write_response(
    stream: &mut TcpStream,
    status: u16,
    media_type: &str,
    body: &str,
    delivery: &ResponseDelivery,
) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let ResponseDelivery::CompleteWithHeaders(headers) = delivery {
        for (name, value) in headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    match delivery {
        ResponseDelivery::Complete | ResponseDelivery::CompleteWithHeaders(_) => {
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
        ResponseDelivery::ResetAfter(body_bytes) => {
            let end = (*body_bytes).min(body.len());
            let _ = stream.write_all(&body.as_bytes()[..end]);
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
        ResponseDelivery::Trickle { chunk_bytes, delay } => {
            for chunk in body.as_bytes().chunks(*chunk_bytes) {
                if stream
                    .write_all(chunk)
                    .and_then(|_| stream.flush())
                    .is_err()
                {
                    return;
                }
                std::thread::sleep(*delay);
            }
        }
    }
}

/// A token send over loopback TCP, the client the tests drive the token
/// endpoint with. The socket work is blocking, so the send runs it on
/// the blocking pool over owned copies of the request's parts; on the
/// blocking thread, credential bytes go from the copied zeroizing
/// buffer straight to the socket.
pub struct LoopbackSend {
    /// How long to wait for the answer.
    pub timeout: Duration,
}

impl LoopbackSend {
    /// A send with the platform's default request timeout.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}

impl Default for LoopbackSend {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSend for LoopbackSend {
    fn send<'a>(
        &'a self,
        request: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>> {
        let url = request.url.clone();
        let authentication = request.authentication.clone();
        let body = request.body.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                send_blocking(&url, &authentication, &body, timeout)
            })
            .await
            .map_err(|_| TransportFailure::Transport(TransportKind::Exchange))?
        })
    }
}

/// The blocking half of one loopback send.
fn send_blocking(
    url: &str,
    authentication: &TokenClientAuthentication,
    body: &ProtectedText,
    timeout: Duration,
) -> Result<TokenWire, TransportFailure> {
    let (host, port, path) =
        split_http_url(url).ok_or(TransportFailure::Transport(TransportKind::Connect))?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|_| TransportFailure::Transport(TransportKind::Connect))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| TransportFailure::Transport(TransportKind::Exchange))?;
    // The transport applies the fixed scheme: the typed authentication
    // carries the payload alone, and the wire carries the whole header
    // value, the way the engine's outbound client renders it.
    let authorization = match authentication {
        TokenClientAuthentication::None => None,
        TokenClientAuthentication::BasicHeader { payload } => {
            let mut value = Zeroizing::new(Vec::with_capacity(6 + payload.as_bytes().len()));
            value.extend_from_slice(b"Basic ");
            value.extend_from_slice(payload.as_bytes());
            Some(value)
        }
    };
    let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: {TOKEN_REQUEST_ACCEPT}\r\nContent-Type: {TOKEN_REQUEST_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| match &authorization {
            None => Ok(()),
            Some(value) => stream
                .write_all(b"authorization: ")
                .and_then(|_| stream.write_all(value.as_slice()))
                .and_then(|_| stream.write_all(b"\r\n")),
        })
        .and_then(|_| stream.write_all(b"\r\n"))
        .and_then(|_| stream.write_all(body.as_bytes()))
        .and_then(|_| stream.flush())
        .map_err(|_| TransportFailure::Transport(TransportKind::Exchange))?;
    read_token_wire(&mut stream)
}

/// Split one absolute loopback `http` URL into host, port, and path.
fn split_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host.to_owned(), port.parse().ok()?),
        None => (authority.to_owned(), 80),
    };
    Some((host, port, path))
}

/// Read one HTTP/1.1 response as a [`TokenWire`].
fn read_token_wire(stream: &mut TcpStream) -> Result<TokenWire, TransportFailure> {
    let mut buffer = Vec::new();
    let mut chunk = [0; 1024];
    let head_end = loop {
        if let Some(position) = find_head_end(&buffer) {
            break position;
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|_| TransportFailure::Transport(TransportKind::Timeout))?;
        if read == 0 {
            return Err(TransportFailure::Transport(TransportKind::Exchange));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 64 * 1024 + 1024 {
            return Err(TransportFailure::Transport(TransportKind::ResponseTooLarge));
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(TransportFailure::Transport(TransportKind::Exchange))?;
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or(TransportFailure::Transport(TransportKind::Exchange))?;
    let media_type = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.trim().to_owned());
    let content_length: usize = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| TransportFailure::Transport(TransportKind::Timeout))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > 16 * 1024 {
            return Err(TransportFailure::Transport(TransportKind::ResponseTooLarge));
        }
    }
    body.truncate(content_length);
    Ok(TokenWire {
        status,
        media_type,
        body: Zeroizing::new(body),
    })
}

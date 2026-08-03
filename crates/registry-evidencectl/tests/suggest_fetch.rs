//! Reading an OpenAPI document from a URL: which URLs are fetched at all, and
//! what happens to the response.
//!
//! Every test here is offline. The policy half is a pure function over a URL
//! string, and the transport half runs against a throwaway HTTP server bound
//! to a loopback port in this process, which is also the one case where plain
//! `http` is permitted. Nothing in this file reaches a public host, so the
//! suite stays hermetic and runs the same on a machine with no network.

#[path = "../src/suggest/fetch.rs"]
mod fetch;
// `openapi.rs` pulls in the whole pipeline's type vocabulary; this binary
// exercises the loading slice of it.
#[allow(dead_code)]
#[path = "../src/suggest/openapi.rs"]
mod openapi;
#[allow(dead_code)]
#[path = "../src/suggest/types.rs"]
mod types;

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
};

use types::SpecSource;

// --- which URLs are fetched --------------------------------------------------

#[test]
fn an_https_url_is_read_as_a_url() {
    let source = fetch::spec_source("https://api.example.test/openapi.yaml").expect("accepted");
    assert!(matches!(source, SpecSource::Url(_)));
    assert_eq!(source.display(), "https://api.example.test/openapi.yaml");
}

/// The URL test is for a scheme at the front of the argument, so an ordinary
/// path is still a path even when it contains the characters a URL uses.
#[test]
fn a_path_is_read_as_a_path() {
    for argument in [
        "openapi.yaml",
        "./specs/openapi.yaml",
        "/srv/specs/openapi.yaml",
        "specs/http://not-a-url.yaml",
    ] {
        let source = fetch::spec_source(argument).expect("accepted");
        assert!(
            matches!(source, SpecSource::File(_)),
            "`{argument}` should be read as a file"
        );
    }
}

/// A description read in the clear can be tampered with, and it decides which
/// leaves the operator is offered, so the projection a drafted source ends up
/// reading is only as trustworthy as the transport that carried it. This is
/// the same rule the runtime applies to the source URLs it will itself call.
#[test]
fn plain_http_to_a_host_that_is_not_loopback_is_refused() {
    for url in [
        "http://api.example.test/openapi.yaml",
        "http://192.0.2.10/openapi.yaml",
        "http://localhost:3000/openapi.yaml",
    ] {
        let error = fetch::spec_source(url).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("loopback"),
            "`{url}` message was: {message}"
        );
    }
}

#[test]
fn plain_http_to_a_numeric_loopback_host_is_accepted() {
    for url in [
        "http://127.0.0.1:8080/openapi.yaml",
        "http://[::1]:8080/openapi.yaml",
    ] {
        let source = fetch::spec_source(url).unwrap_or_else(|error| panic!("{url}: {error:#}"));
        assert!(matches!(source, SpecSource::Url(_)), "`{url}` was refused");
    }
}

/// The refusal must not quote the URL back: what makes it unacceptable is the
/// credential inside it, and a message is printed to a terminal and kept in a
/// scrollback buffer.
#[test]
fn a_url_carrying_credentials_is_refused_without_echoing_them() {
    let error =
        fetch::spec_source("https://reader:hunter2@api.example.test/openapi.yaml").unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("credentials"), "message was: {message}");
    assert!(
        !message.contains("hunter2") && !message.contains("reader"),
        "the refusal echoed the credential: {message}"
    );
}

#[test]
fn a_scheme_that_is_not_http_is_refused() {
    for url in [
        "ftp://example.test/openapi.yaml",
        "file:///tmp/openapi.yaml",
    ] {
        let error = fetch::spec_source(url).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("not fetched"),
            "`{url}` message was: {message}"
        );
    }
}

// --- what happens to the response --------------------------------------------

#[test]
fn a_document_served_over_loopback_is_opened_exactly_as_the_file_would_be() {
    let fixture = fixture_text("records-3.0.yaml");
    let address = serve(move |_target| ok(&fixture, "application/yaml"));

    let from_url = openapi::Spec::open(&url_source(address, "/openapi.yaml")).expect("opens");
    let from_file =
        openapi::Spec::open(&SpecSource::File(fixture_path("records-3.0.yaml"))).expect("opens");

    assert_eq!(
        from_url
            .operations()
            .into_iter()
            .map(|summary| summary.key)
            .collect::<Vec<_>>(),
        from_file
            .operations()
            .into_iter()
            .map(|summary| summary.key)
            .collect::<Vec<_>>()
    );
}

/// A description behind authentication answers with a status, not a document.
/// Saying which status came back is what tells the operator to fetch it
/// themselves rather than to go looking for a malformed file.
#[test]
fn a_non_success_status_is_reported_with_its_code() {
    let address = serve(|_target| {
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    });

    let error = openapi::Spec::open(&url_source(address, "/openapi.yaml")).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("401") && message.contains("authentication"),
        "message was: {message}"
    );
}

/// The ceiling is enforced while reading rather than from the declared length,
/// so a response that never says how long it is cannot talk this into
/// buffering whatever the server feels like sending.
#[test]
fn a_body_past_the_ceiling_is_refused() {
    let declared = serve(|_target| ok(&"x".repeat(4096), "application/yaml"));
    let undeclared = serve(|_target| {
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/yaml\r\nConnection: close\r\n\r\n"
                .to_vec();
        response.extend_from_slice("x".repeat(4096).as_bytes());
        response
    });

    for address in [declared, undeclared] {
        let SpecSource::Url(url) = url_source(address, "/openapi.yaml") else {
            unreachable!("built as a URL")
        };
        let error = fetch::get(&url, 512).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("512 byte limit"), "message was: {message}");
    }
}

/// A published description is very often a stable URL pointing at a versioned
/// one, so a redirect is followed; where it lands is checked under the same
/// rule as where it started.
#[test]
fn a_redirect_is_followed_and_its_destination_is_read() {
    let fixture = fixture_text("records-3.0.yaml");
    let destination = serve(move |_target| ok(&fixture, "application/yaml"));
    let entry = serve(move |_target| {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{destination}/versioned.yaml\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    });

    let spec = openapi::Spec::open(&url_source(entry, "/latest.yaml")).expect("opens");
    assert!(!spec.operations().is_empty());
}

// --- helpers -----------------------------------------------------------------

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/openapi")
        .join(name)
}

fn fixture_text(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).expect("fixture readable")
}

fn url_source(address: SocketAddr, path: &str) -> SpecSource {
    fetch::spec_source(&format!("http://{address}{path}")).expect("loopback URL accepted")
}

fn ok(body: &str, content_type: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Binds a loopback port and answers every request with `respond`, returning
/// the address it bound.
///
/// The serving thread is left running for the rest of the test binary's life:
/// it holds nothing but a socket, and a test that finished has no way to be
/// waiting on it. Requests are read only far enough to know what was asked
/// for, which is all any test here needs to decide what to send back.
fn serve(respond: impl Fn(&str) -> Vec<u8> + Send + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binds a loopback port");
    let address = listener.local_addr().expect("has an address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            handle(stream, &respond);
        }
    });
    address
}

fn handle(mut stream: TcpStream, respond: &impl Fn(&str) -> Vec<u8>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clones the stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {}
            Err(_) => return,
        }
    }
    let target = request_line.split_whitespace().nth(1).unwrap_or("/");
    let response = respond(target);
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

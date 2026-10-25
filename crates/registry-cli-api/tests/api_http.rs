use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::mpsc,
    thread,
};

use registry_cli_api::{run_api, ApiArgs, ApiError, LocalConnection};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn server(response: &'static [u8]) -> (String, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = mpsc::channel();
    thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = socket.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(headers_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers_end = headers_end + 4;
                let headers = String::from_utf8_lossy(&request[..headers_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .and_then(|length| length.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= headers_end + content_length {
                    break;
                }
            }
        }
        sent.send(request).unwrap();
        socket.write_all(response).unwrap();
    });
    (format!("http://{address}/deployment/prefix"), received)
}

fn api_args(path: &str, output: PathBuf) -> ApiArgs {
    ApiArgs {
        path: path.to_owned(),
        project: None,
        client: None,
        connection: None,
        url: None,
        token_file: None,
        ca_file: None,
        method: None,
        input: None,
        header: Vec::new(),
        accept: None,
        output: Some(output),
        include: false,
        idempotency_key: None,
        if_match: None,
    }
}

#[test]
fn post_preserves_the_deployment_prefix_query_and_explicit_headers() {
    let response =
        b"HTTP/1.1 201 Created\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncreated!";
    let (base_url, request) = server(response);
    let temporary = TempDir::new().unwrap();
    let input = temporary.path().join("input.json");
    let header = temporary.path().join("header.txt");
    let output = temporary.path().join("response.bin");
    fs::write(&input, br#"{"name":"A"}"#).unwrap();
    fs::write(&header, "opaque-header-value\n").unwrap();
    let token = temporary.path().join("token");
    fs::write(&token, "canary-token\n").unwrap();

    let mut args = api_args("/v1/records?search=two%20words&limit=2", output.clone());
    args.input = Some(input);
    args.url = Some(base_url);
    args.token_file = Some(token);
    args.accept = Some("application/json".to_owned());
    args.header = vec![format!("X-Opaque: @{}", header.display())];
    args.idempotency_key = Some("operation-1".to_owned());
    args.if_match = Some("\"revision-3\"".to_owned());
    run_api("breg", args, |_, _| unreachable!("--url bypasses resolver")).unwrap();

    let request = String::from_utf8(request.recv().unwrap()).unwrap();
    assert!(request
        .starts_with("POST /deployment/prefix/v1/records?search=two%20words&limit=2 HTTP/1.1\r\n"));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer canary-token\r\n"));
    let lower = request.to_ascii_lowercase();
    assert!(lower.contains("idempotency-key: operation-1\r\n"));
    assert!(lower.contains("if-match: \"revision-3\"\r\n"));
    assert!(lower.contains("x-opaque: opaque-header-value\r\n"));
    assert!(request.ends_with(r#"{"name":"A"}"#));
    assert_eq!(fs::read(output).unwrap(), b"created!");
}

#[test]
fn automatic_credentials_cannot_be_replaced_by_a_repeated_header() {
    let temporary = TempDir::new().unwrap();
    let mut args = api_args("v1/status", temporary.path().join("out"));
    let token = temporary.path().join("token");
    fs::write(&token, "canary-token").unwrap();
    args.url = Some("http://127.0.0.1:9".to_owned());
    args.token_file = Some(token);
    args.header = vec!["Authorization: Bearer attacker-controlled".to_owned()];
    let error = run_api("breg", args, |_, _| unreachable!("--url bypasses resolver")).unwrap_err();
    assert_eq!(error.exit_code(), 2);
    assert!(!error.to_string().contains("canary-token"));
}

#[test]
fn anonymous_requests_accept_one_explicit_authorization_header_from_each_supported_input() {
    let temporary = TempDir::new().unwrap();
    let complete_header = temporary.path().join("complete-header");
    let header_value = temporary.path().join("header-value");
    fs::write(
        &complete_header,
        "Authorization: Bearer complete-file-canary\n",
    )
    .unwrap();
    fs::write(&header_value, "Bearer value-file-canary\n").unwrap();

    for (argument, expected) in [
        (
            "Authorization: Bearer inline-canary".to_owned(),
            "Bearer inline-canary",
        ),
        (
            format!("@{}", complete_header.display()),
            "Bearer complete-file-canary",
        ),
        (
            format!("Authorization: @{}", header_value.display()),
            "Bearer value-file-canary",
        ),
    ] {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let (base_url, request) = server(response);
        let mut args = api_args("v1/status", temporary.path().join("out"));
        args.url = Some(base_url);
        args.header = vec![argument];
        run_api("breg", args, |_, _| unreachable!("--url bypasses resolver")).unwrap();

        let request = String::from_utf8(request.recv().unwrap()).unwrap();
        let authorization = request
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.trim_start())
            .collect::<Vec<_>>();
        assert_eq!(authorization, [expected]);
    }
}

#[test]
fn local_connection_headers_cannot_be_replaced_by_cli_headers() {
    let temporary = TempDir::new().unwrap();
    let project = temporary.path().join("casework-project");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("casework.yaml"), "marker").unwrap();
    let mut args = api_args("v1/status", temporary.path().join("out"));
    args.project = Some(project);
    args.client = Some("staff-client".to_owned());
    args.header = vec!["Registry-Casework-Profile: attacker-profile".to_owned()];

    let error = run_api("casework", args, |_, _| {
        LocalConnection::anonymous("http://127.0.0.1:9".to_owned())
            .and_then(|connection| connection.with_header("Registry-Casework-Profile", "staff"))
            .map_err(|error| error.to_string())
    })
    .expect_err("a CLI header must not override a local connection header");
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn redirect_answers_are_returned_without_following_them() {
    let response = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 8\r\nConnection: close\r\n\r\nredirect";
    let (base_url, request) = server(response);
    let temporary = TempDir::new().unwrap();
    let output = temporary.path().join("out");
    let mut args = api_args("v1/status", output.clone());
    args.url = Some(base_url);
    let error = run_api("breg", args, |_, _| unreachable!("--url bypasses resolver")).unwrap_err();
    assert_eq!(error.exit_code(), 1);
    request.recv().unwrap();
    assert_eq!(fs::read(output).unwrap(), b"redirect");
}

#[test]
fn response_bodies_are_bounded() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 9000000\r\nConnection: close\r\n\r\n";
    let (base_url, request) = server(response);
    let temporary = TempDir::new().unwrap();
    let mut args = api_args("v1/status", temporary.path().join("out"));
    args.url = Some(base_url);
    let error = run_api("breg", args, |_, _| unreachable!("--url bypasses resolver")).unwrap_err();
    request.recv().unwrap();
    assert_eq!(error.exit_code(), 3);
    assert!(matches!(error, ApiError::ResponseTooLarge));
}

#[test]
fn bearer_connection_debug_and_failures_do_not_disclose_the_token() {
    let connection = LocalConnection::bearer(
        "https://registry.example.test/base".to_owned(),
        Zeroizing::new("debug-canary-token".to_owned()),
    )
    .unwrap();
    assert!(!format!("{connection:?}").contains("debug-canary-token"));
    assert!(LocalConnection::bearer(
        "http://registry.example.test".to_owned(),
        Zeroizing::new("error-canary-token".to_owned()),
    )
    .unwrap_err()
    .to_string()
    .contains("HTTPS"));
}

#[test]
fn api_args_debug_redacts_request_values() {
    let temporary = TempDir::new().unwrap();
    let mut args = api_args("v1/people?name=path-canary", temporary.path().join("out"));
    args.url = Some("https://url-canary.example.test".to_owned());
    args.header = vec!["Authorization: header-canary".to_owned()];
    args.idempotency_key = Some("idempotency-canary".to_owned());
    args.if_match = Some("if-match-canary".to_owned());
    let debug = format!("{args:?}");
    for canary in [
        "path-canary",
        "url-canary",
        "header-canary",
        "idempotency-canary",
        "if-match-canary",
    ] {
        assert!(!debug.contains(canary), "debug disclosed {canary}: {debug}");
    }
}

#[test]
fn paths_and_host_headers_cannot_escape_the_selected_endpoint() {
    let temporary = TempDir::new().unwrap();
    for path in [
        "https:/other.example/path",
        r"\\other.example\path",
        "%2e%2e/admin",
        "v1/%2E%2E/%2E%2E/admin",
    ] {
        let mut args = api_args(path, temporary.path().join("out"));
        args.url = Some("https://registry.example.test/deployment/prefix".to_owned());
        let error = run_api("breg", args, |_, _| unreachable!("explicit URL"))
            .expect_err("an escaping path must be refused");
        assert_eq!(error.exit_code(), 2, "{path}: {error}");
    }

    let mut args = api_args("v1/status", temporary.path().join("out"));
    args.url = Some("https://registry.example.test/deployment/prefix".to_owned());
    args.header = vec!["Host: other.example.test".to_owned()];
    let error = run_api("breg", args, |_, _| unreachable!("explicit URL"))
        .expect_err("Host override must be refused");
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn a_complete_header_file_supplies_multiple_header_lines() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let (base_url, request) = server(response);
    let temporary = TempDir::new().unwrap();
    let headers = temporary.path().join("headers.txt");
    fs::write(&headers, "X-First: one\nX-Second: two\n").unwrap();
    let mut args = api_args("v1/status", temporary.path().join("out"));
    args.url = Some(base_url);
    args.header = vec![format!("@{}", headers.display())];
    run_api("breg", args, |_, _| unreachable!("explicit URL")).unwrap();
    let request = String::from_utf8(request.recv().unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(request.contains("x-first: one\r\n"));
    assert!(request.contains("x-second: two\r\n"));
}

#[test]
fn an_invalid_explicit_ca_bundle_is_refused_before_connecting() {
    let temporary = TempDir::new().unwrap();
    let ca = temporary.path().join("institution-ca.pem");
    fs::write(&ca, "not a PEM certificate\n").unwrap();
    let mut args = api_args("v1/status", temporary.path().join("out"));
    args.url = Some("https://registry.example.test/api".to_owned());
    args.ca_file = Some(ca);

    let error = run_api("breg", args, |_, _| unreachable!("explicit URL"))
        .expect_err("invalid trust material must be refused locally");
    assert_eq!(error.exit_code(), 3);
    assert!(!error.to_string().contains("not a PEM certificate"));
}

#[allow(dead_code)]
fn _read_one_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    stream.read_to_end(&mut request).unwrap();
    request
}

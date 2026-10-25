use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0, "request ended before its declared body");
        request.extend_from_slice(&buffer[..count]);
        let Some(headers_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
            continue;
        };
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
            return request;
        }
    }
}

#[cfg(unix)]
fn run_without_blocking(command: &mut Command, context: &[String]) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("command blocked while opening {context:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn api_and_connection_are_product_scoped_commands() {
    for command in ["api", "connection"] {
        let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .args([command, "--help"])
            .output()
            .expect("run bregctl");
        assert!(
            output.status.success(),
            "bregctl {command} --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn raw_api_rejects_the_global_report_format() {
    for format in ["human", "json"] {
        let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .args(["api", "/health", "--format", format])
            .output()
            .expect("run bregctl");
        assert_eq!(output.status.code(), Some(2), "format: {format}");
        assert!(output.stdout.is_empty(), "format: {format}");
    }
}

#[test]
fn raw_api_response_bypasses_the_ctl_report_envelope() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stand-in API");
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept API request");
        let mut request = [0; 4096];
        let read = stream.read(&mut request).expect("read API request");
        assert!(
            String::from_utf8_lossy(&request[..read]).starts_with("GET /raw HTTP/1.1"),
            "unexpected request"
        );
        let body = br#"{"value":"raw"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["api", "/raw", "--url", &format!("http://{address}")])
        .output()
        .expect("run bregctl");
    server.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, br#"{"value":"raw"}"#);
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[cfg(unix)]
#[test]
fn raw_api_refuses_fifo_file_inputs_without_blocking() {
    let temporary = tempfile::tempdir().unwrap();
    let fifo = temporary.path().join("blocking-input");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());

    for arguments in [
        vec!["--token-file".to_owned(), fifo.display().to_string()],
        vec!["--ca-file".to_owned(), fifo.display().to_string()],
        vec!["--input".to_owned(), fifo.display().to_string()],
        vec!["--header".to_owned(), format!("@{}", fifo.display())],
    ] {
        let output = run_without_blocking(
            Command::new(env!("CARGO_BIN_EXE_bregctl"))
                .args(["api", "/raw", "--url", "http://127.0.0.1:9"])
                .args(&arguments),
            &arguments,
        );
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("regular file"), "{arguments:?}: {error}");
    }
}

#[cfg(unix)]
#[test]
fn connection_commands_refuse_fifo_stores_without_blocking() {
    let temporary = tempfile::tempdir().unwrap();
    let checked_fifo = temporary.path().join("checked-connections");
    assert!(Command::new("mkfifo")
        .arg(&checked_fifo)
        .status()
        .unwrap()
        .success());

    let config_root = temporary.path().join("config");
    let saved_fifo = config_root.join("registrystack/connections.yaml");
    std::fs::create_dir_all(saved_fifo.parent().unwrap()).unwrap();
    assert!(Command::new("mkfifo")
        .arg(&saved_fifo)
        .status()
        .unwrap()
        .success());

    for (arguments, config) in [
        (
            vec![
                "connection".to_owned(),
                "check".to_owned(),
                "--file".to_owned(),
                checked_fifo.display().to_string(),
            ],
            None,
        ),
        (
            vec!["connection".to_owned(), "list".to_owned()],
            Some(config_root.as_path()),
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bregctl"));
        command
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(config) = config {
            command.env("XDG_CONFIG_HOME", config);
        }
        let output = run_without_blocking(&mut command, &arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("regular file"), "{arguments:?}: {error}");
    }
}

#[test]
fn raw_api_accepts_a_regular_token_file_and_request_body_from_standard_input() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stand-in API");
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept API request");
        let request = read_request(&mut stream);
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("POST /raw HTTP/1.1\r\n"), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer regular-file-token\r\n"),
            "{request}"
        );
        assert!(request.ends_with(r#"{"from":"stdin"}"#), "{request}");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });

    let temporary = tempfile::tempdir().unwrap();
    let token_target = temporary.path().join("token-target");
    std::fs::write(&token_target, "regular-file-token\n").unwrap();
    #[cfg(unix)]
    let token = {
        let token = temporary.path().join("token-link");
        std::os::unix::fs::symlink(&token_target, &token).unwrap();
        token
    };
    #[cfg(not(unix))]
    let token = token_target;
    let mut child = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["api", "/raw", "--url", &format!("http://{address}")])
        .args(["--token-file", token.to_str().unwrap(), "--input", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"from":"stdin"}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ok");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn connection_check_reports_positioned_configuration_errors_as_json() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("connections.yaml");
    std::fs::write(
        &path,
        "apiVersion: id.registrystack.org/formats/platform/cli-connections/v1alpha1\nkind: PlatformCliConnections\nunknown: private-value-canary\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["connection", "check", "--file"])
        .arg(&path)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["kind"], "PlatformCliConnectionCheckReport");
    assert_eq!(report["diagnostics"][0]["code"], "config.unknown-key");
    assert_eq!(report["diagnostics"][0]["source"]["line"], 3);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-value-canary"));
    assert!(output.stderr.is_empty());
}

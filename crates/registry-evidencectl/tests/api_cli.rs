use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    process::Command,
};

#[test]
fn api_and_connection_are_product_scoped_commands() {
    for command in ["api", "connection"] {
        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args([command, "--help"])
            .output()
            .expect("run evidencectl");
        assert!(
            output.status.success(),
            "evidencectl {command} --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn raw_api_rejects_the_global_report_format() {
    for format in ["human", "json"] {
        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["api", "/health", "--format", format])
            .output()
            .expect("run evidencectl");
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

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["api", "/raw", "--url", &format!("http://{address}")])
        .output()
        .expect("run evidencectl");
    server.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, br#"{"value":"raw"}"#);
    assert!(output.stderr.is_empty(), "{output:?}");
}

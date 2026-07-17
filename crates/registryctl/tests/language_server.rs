// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    process::{ChildStdin, ChildStdout, Command, Stdio},
};

use serde_json::{json, Value};

fn send(stdin: &mut ChildStdin, message: Value) {
    let body = serde_json::to_vec(&message).unwrap();
    write!(stdin, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
    stdin.write_all(&body).unwrap();
    stdin.flush().unwrap();
}

fn receive(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut content_length = None;
    loop {
        let mut header = String::new();
        stdout.read_line(&mut header).unwrap();
        assert!(
            !header.is_empty(),
            "registryctl closed language-server stdout"
        );
        if header == "\r\n" {
            break;
        }
        if let Some(length) = header.strip_prefix("Content-Length:") {
            content_length = Some(length.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; content_length.expect("response has Content-Length")];
    stdout.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[test]
fn authoring_language_server_speaks_lsp_without_cli_output() {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("registry-stack.yaml"),
        "version: 1\nregistry: { id: demo }\nservices: {}\n",
    )
    .unwrap();
    let root_uri = format!("file://{}", project.path().display());

    let mut child = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args(["authoring", "language-server"])
        .current_dir(project.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": root_uri,
                "capabilities": {},
                "workspaceFolders": [{ "uri": root_uri, "name": "demo" }]
            }
        }),
    );
    let initialize = receive(&mut stdout);
    assert_eq!(initialize["id"], 1);
    assert_eq!(
        initialize["result"]["capabilities"]["definitionProvider"],
        true
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": null }),
    );
    let shutdown = receive(&mut stdout);
    assert_eq!(shutdown["id"], 2);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

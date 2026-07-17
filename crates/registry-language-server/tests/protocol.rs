// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    process::{ChildStdin, ChildStdout, Command, Stdio},
};

use serde_json::{json, Value};
use tempfile::TempDir;
use tower_lsp_server::ls_types::Uri;

fn write_project() -> TempDir {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("integrations/people")).unwrap();
    fs::write(
        temp.path().join("registry-stack.yaml"),
        r#"version: 1
registry: { id: demo }
integrations:
  people: { file: integrations/people/integration.yaml }
services:
  check:
    consultations:
      lookup: { integration: people }
    claims:
      active: { output: lookup.active }
    credential_profiles:
      status: { claims: [active, missing] }
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("integrations/people/integration.yaml"),
        "version: 1\nid: upstream-people\n",
    )
    .unwrap();
    temp
}

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
        assert!(!header.is_empty(), "language server closed stdout");
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

fn receive_response(stdout: &mut BufReader<ChildStdout>, id: i64) -> Value {
    for _ in 0..50 {
        let message = receive(stdout);
        if message.get("id").and_then(Value::as_i64) == Some(id) {
            return message;
        }
    }
    panic!("language server did not return response {id}");
}

#[test]
fn serves_definition_references_and_workspace_symbols_over_stdio() {
    let project = write_project();
    let root_uri = Uri::from_file_path(project.path()).unwrap().to_string();
    let manifest_path = project
        .path()
        .join("registry-stack.yaml")
        .canonicalize()
        .unwrap();
    let manifest_uri = Uri::from_file_path(manifest_path).unwrap().to_string();
    let integration_path = project
        .path()
        .join("integrations/people/integration.yaml")
        .canonicalize()
        .unwrap();
    let integration_uri = Uri::from_file_path(integration_path).unwrap().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-language-server"))
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
    let initialize = receive_response(&mut stdout, 1);
    assert_eq!(
        initialize.pointer("/result/capabilities/definitionProvider"),
        Some(&Value::Bool(true))
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );
    let mut published_missing_reference = false;
    for _ in 0..3 {
        let notification = receive(&mut stdout);
        if notification.get("method").and_then(Value::as_str)
            == Some("textDocument/publishDiagnostics")
            && notification.pointer("/params/uri").and_then(Value::as_str)
                == Some(manifest_uri.as_str())
        {
            published_missing_reference = notification
                .pointer("/params/diagnostics")
                .and_then(Value::as_array)
                .is_some_and(|diagnostics| {
                    diagnostics.iter().any(|diagnostic| {
                        diagnostic
                            .get("message")
                            .and_then(Value::as_str)
                            .is_some_and(|message| {
                                message.contains("Unknown claim reference 'missing'")
                            })
                    })
                });
        }
    }
    assert!(published_missing_reference);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/definition",
            "params": {
                "textDocument": { "uri": manifest_uri },
                "position": { "line": 7, "character": 31 }
            }
        }),
    );
    let definition = receive_response(&mut stdout, 2);
    assert_eq!(
        definition.pointer("/result/0/uri").and_then(Value::as_str),
        Some(integration_uri.as_str())
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/references",
            "params": {
                "textDocument": { "uri": integration_uri },
                "position": { "line": 1, "character": 6 },
                "context": { "includeDeclaration": true }
            }
        }),
    );
    let references = receive_response(&mut stdout, 3);
    assert!(
        references
            .get("result")
            .and_then(Value::as_array)
            .is_some_and(|locations| locations.len() >= 3),
        "{references}"
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "workspace/symbol",
            "params": { "query": "active" }
        }),
    );
    let symbols = receive_response(&mut stdout, 4);
    assert_eq!(
        symbols.pointer("/result/0/name").and_then(Value::as_str),
        Some("active")
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 5, "method": "shutdown", "params": null }),
    );
    receive_response(&mut stdout, 5);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const SOURCE: &str = r#"apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: subprocess}
recordTypes:
  - id: person
    fields:
      - {id: name, type: string}
actions:
  - id: update
    execution: {mode: immediate}
    inputs:
      - {id: subject, type: reference, target: person}
    plan:
      type: fixed
      effects: []
accessProfiles: []
"#;

#[test]
fn native_lsp_binary_serves_navigation_and_changed_diagnostics_over_stdio() {
    let project = tempfile::tempdir().expect("temporary BReg project");
    let project_path = project
        .path()
        .canonicalize()
        .expect("project root resolves");
    let path = project_path.join("registry.yaml");
    std::fs::write(&path, SOURCE).expect("fixture writes");
    let project_uri = file_uri(&project_path);
    let document_uri = file_uri(&path);

    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-language-server"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("language-server subprocess starts");
    let mut stdin = child.stdin.take().expect("language-server stdin");
    let stdout = child.stdout.take().expect("language-server stdout");
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        while let Ok(Some(message)) = read_message(&mut reader) {
            if sender.send(message).is_err() {
                break;
            }
        }
    });

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": {},
                "workspaceFolders": [{"uri": project_uri, "name": "project"}]
            }
        }),
    );
    let initialized = receive_until(&receiver, |message| message["id"] == 1);
    assert_eq!(
        initialized["result"]["capabilities"]["definitionProvider"],
        true
    );
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {"textDocument": {
                "uri": document_uri,
                "languageId": "yaml",
                "version": 1,
                "text": SOURCE
            }}
        }),
    );

    let reference = position(SOURCE, "target: person", "person");
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/definition",
            "params": {"textDocument":{"uri":document_uri},"position":reference}
        }),
    );
    let definition = receive_until(&receiver, |message| message["id"] == 2);
    let locations = definition["result"]
        .as_array()
        .expect("definition locations");
    assert_eq!(locations.len(), 1, "{definition}");
    assert_eq!(locations[0]["uri"], document_uri);
    assert_eq!(
        locations[0]["range"]["start"],
        position(SOURCE, "id: person", "person")
    );

    let changed = SOURCE.replace("target: person", "target: missing");
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri":document_uri,"version":2},
                "contentChanges": [{"text":changed}]
            }
        }),
    );
    let diagnostics = receive_until(&receiver, |message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["uri"] == document_uri
            && message["params"]["diagnostics"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
    });
    assert!(diagnostics["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["message"]
            .as_str()
            .is_some_and(|message| message.contains("missing"))));

    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":3,"method":"shutdown","params":null}),
    );
    receive_until(&receiver, |message| message["id"] == 3);
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"exit","params":null}),
    );
    drop(stdin);
    assert!(child.wait().expect("language server exits").success());
    reader.join().expect("stdout reader joins");
}

fn send(stdin: &mut ChildStdin, message: Value) {
    let body = serde_json::to_vec(&message).expect("message serializes");
    write!(stdin, "Content-Length: {}\r\n\r\n", body.len()).expect("header writes");
    stdin.write_all(&body).expect("body writes");
    stdin.flush().expect("message flushes");
}

fn read_message(reader: &mut impl BufRead) -> std::io::Result<Option<Value>> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length =
                Some(value.trim().parse::<usize>().map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                })?);
        }
    }
    let length = content_length.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing Content-Length")
    })?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn receive_until(receiver: &Receiver<Value>, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let message = receiver
            .recv_timeout(remaining)
            .expect("language server responds before the deadline");
        if predicate(&message) {
            return message;
        }
    }
}

fn file_uri(path: &std::path::Path) -> String {
    format!("file://{}", path.display())
}

fn position(source: &str, occurrence: &str, token: &str) -> Value {
    let start = source.find(occurrence).expect("occurrence exists")
        + occurrence.find(token).expect("token exists");
    let prefix = &source[..start];
    json!({
        "line": prefix.bytes().filter(|byte| *byte == b'\n').count(),
        "character": prefix.rsplit_once('\n').map_or(prefix.len(), |(_, line)| line.len())
    })
}

// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const API_VERSION: &str = "id.registrystack.org/formats/platform/workspace-analysis/v1alpha1";
const ACTION: &str = "kind: PlatformAction\ntitle: \"Apply 🩺\"\nname: apply\n";
const SERVICE: &str = "kind: PlatformService\nname: nursing\nmap:\n  steps:\n    - { label: \"🩺\", action: apply }\n";
const NATIVE: &str =
    "kind: BRegProject\nproject: {id: nursing}\nrecordTypes:\n  - id: practitioner\n";
const ACTION_URI: &str = "registry-studio://authorized/actions/apply.yaml";
const SERVICE_URI: &str = "registry-studio://authorized/services/nursing.yaml";
const NATIVE_URI: &str = "file:///definitely-not-present/native/breg/nursing.yaml";

#[test]
fn authorized_workspace_lsp_is_stateless_and_uses_exact_snapshot_bytes() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-language-server"))
        .arg("--workspace-lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("authorized language-server subprocess starts");
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
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}),
    );
    let initialized = receive_until(&receiver, |message| message["id"] == 1);
    assert_eq!(
        initialized["result"]["capabilities"]["experimental"]["registryStudioAuthorizedQuery"],
        true
    );
    assert_eq!(
        initialized["result"]["capabilities"]["executeCommandProvider"]["commands"],
        json!([
            "registryStudio.workspaceV1.snapshot",
            "registryStudio.workspaceV1.impact"
        ])
    );
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
    );

    let ready_authorization = authorization(snapshot_request("revision-1"));
    let action_position = position(ACTION, "name: apply", "apply");
    let service_position = position(SERVICE, "action: apply", "apply");
    assert_eq!(service_position, json!({"line":4,"character":29}));
    let definition = authorized_query(
        2,
        ready_authorization.clone(),
        "textDocument/definition",
        json!({"textDocument":{"uri":SERVICE_URI},"position":service_position}),
    );
    send(&mut stdin, definition);
    let definition = receive_until(&receiver, |message| message["id"] == 2);
    assert_eq!(
        definition["result"],
        json!([{"uri":ACTION_URI,"range":{"start":action_position,"end":position_end(ACTION, "name: apply", "apply")}}])
    );

    send(
        &mut stdin,
        authorized_query(
            3,
            ready_authorization,
            "textDocument/references",
            json!({
                "textDocument":{"uri":ACTION_URI},
                "position":action_position,
                "context":{"includeDeclaration":true}
            }),
        ),
    );
    let references = receive_until(&receiver, |message| message["id"] == 3);
    let locations = references["result"]
        .as_array()
        .expect("reference locations");
    assert_eq!(locations.len(), 2, "{references}");
    assert!(locations
        .iter()
        .any(|location| location["uri"] == SERVICE_URI));

    // A later unavailable authorization must not reuse the preceding exact snapshot.
    send(
        &mut stdin,
        authorized_query(
            4,
            json!({"status":"unavailable","code":"authorization-revoked","message":"Workspace authorization was revoked."}),
            "textDocument/definition",
            json!({"textDocument":{"uri":SERVICE_URI},"position":service_position}),
        ),
    );
    let revoked = receive_until(&receiver, |message| message["id"] == 4);
    assert_eq!(revoked["error"]["code"], -32001);
    assert_eq!(revoked["error"]["data"]["code"], "authorization-revoked");

    // The native source URI does not exist on the host. Analysis must use only supplied bytes.
    send(
        &mut stdin,
        authorized_query(
            5,
            authorization(snapshot_request("revision-2")),
            "workspace/executeCommand",
            json!({"command":"registryStudio.workspaceV1.snapshot","arguments":[]}),
        ),
    );
    let snapshot = receive_until(&receiver, |message| message["id"] == 5);
    assert_eq!(snapshot["result"]["status"], "available", "{snapshot}");
    assert_eq!(snapshot["result"]["snapshot"]["revision"], "revision-2");
    assert!(snapshot["result"]["coverage"]["gaps"]
        .as_array()
        .expect("coverage gaps")
        .iter()
        .any(|gap| gap["file"] == "native/breg/nursing.yaml"));

    let current = snapshot["result"]["snapshot"].clone();
    send(
        &mut stdin,
        authorized_query(
            6,
            authorization_with_before(
                snapshot_request("revision-2"),
                snapshot_request("revision-1"),
            ),
            "workspace/executeCommand",
            json!({
                "command":"registryStudio.workspaceV1.impact",
                "arguments":[{"snapshot":current,"compareWithBase":true}]
            }),
        ),
    );
    let impact = receive_until(&receiver, |message| message["id"] == 6);
    assert_eq!(impact["result"]["status"], "available", "{impact}");
    assert_eq!(
        impact["result"]["impact"]["before"]["revision"],
        "revision-1"
    );

    send(
        &mut stdin,
        authorized_query(
            7,
            authorization(snapshot_request("revision-2")),
            "workspace/executeCommand",
            json!({
                "command":"registryStudio.workspaceV1.impact",
                "arguments":[{"snapshot":{"workspaceBinding":"workspace:test","revision":"stale","contentHash":"0"}}]
            }),
        ),
    );
    let stale = receive_until(&receiver, |message| message["id"] == 7);
    assert_eq!(stale["result"]["status"], "stale", "{stale}");

    let mut duplicate_binding = authorization(snapshot_request("revision-2"));
    duplicate_binding["uriBindings"]
        .as_array_mut()
        .expect("URI bindings")
        .push(json!({"path":"actions/apply.yaml","uri":"registry-studio://duplicate/actions/apply.yaml"}));
    send(
        &mut stdin,
        authorized_query(
            8,
            duplicate_binding,
            "workspace/executeCommand",
            json!({"command":"registryStudio.workspaceV1.snapshot","arguments":[]}),
        ),
    );
    let duplicate = receive_until(&receiver, |message| message["id"] == 8);
    assert_eq!(duplicate["error"]["code"], -32602, "{duplicate}");

    let mut outside_binding = authorization(snapshot_request("revision-2"));
    outside_binding["uriBindings"]
        .as_array_mut()
        .expect("URI bindings")
        .push(json!({"path":"outside/not-captured.yaml","uri":"registry-studio://outside/not-captured.yaml"}));
    send(
        &mut stdin,
        authorized_query(
            9,
            outside_binding,
            "workspace/executeCommand",
            json!({"command":"registryStudio.workspaceV1.snapshot","arguments":[]}),
        ),
    );
    let outside = receive_until(&receiver, |message| message["id"] == 9);
    assert_eq!(outside["error"]["code"], -32602, "{outside}");

    let mut opaque_authorization = authorization(binary_native_snapshot_request("revision-3"));
    opaque_authorization["uriBindings"]
        .as_array_mut()
        .expect("URI bindings")
        .retain(|binding| binding["path"] != "native/breg/nursing.yaml");
    send(
        &mut stdin,
        authorized_query(
            10,
            opaque_authorization,
            "workspace/executeCommand",
            json!({"command":"registryStudio.workspaceV1.snapshot","arguments":[]}),
        ),
    );
    let opaque = receive_until(&receiver, |message| message["id"] == 10);
    assert_eq!(opaque["result"]["status"], "available", "{opaque}");
    assert!(opaque["result"]["coverage"]["gaps"]
        .as_array()
        .expect("opaque native coverage")
        .iter()
        .any(|gap| gap["file"] == "native/breg/nursing.yaml"));

    send(
        &mut stdin,
        authorized_query(
            11,
            json!({"status":"ready","after":large_snapshot_request(),"uriBindings":[]}),
            "workspace/executeCommand",
            json!({"command":"registryStudio.workspaceV1.snapshot","arguments":[]}),
        ),
    );
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"$/cancelRequest","params":{"id":11}}),
    );
    let cancelled = receive_until(&receiver, |message| message["id"] == 11);
    assert_eq!(cancelled["error"]["code"], -32800, "{cancelled}");

    // Direct navigation has no authorized payload and must not expose snapshot data.
    send(
        &mut stdin,
        json!({
            "jsonrpc":"2.0","id":12,"method":"textDocument/definition",
            "params":{"textDocument":{"uri":SERVICE_URI},"position":service_position}
        }),
    );
    let direct = receive_until(&receiver, |message| message["id"] == 12);
    assert_eq!(direct["error"]["code"], -32801);

    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":13,"method":"shutdown","params":null}),
    );
    receive_until(&receiver, |message| message["id"] == 13);
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"exit","params":null}),
    );
    drop(stdin);
    assert!(child.wait().expect("language server exits").success());
    reader.join().expect("stdout reader joins");
}

fn snapshot_request(revision: &str) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "operation": "analyze",
        "workspaceBinding": "workspace:test",
        "revision": revision,
        "files": [
            file("actions/apply.yaml", "document", ACTION),
            file("services/nursing.yaml", "document", SERVICE),
            file("native/breg/nursing.yaml", "native", NATIVE)
        ],
        "facts": {
            "definitions": [
                {"scope":"actions","name":"apply","file":"actions/apply.yaml","pointer":"/name"},
                {"scope":"services","name":"nursing","file":"services/nursing.yaml","pointer":"/name"}
            ],
            "mentions": [{
                "source":{"scope":"services","name":"nursing"},
                "target":{"scope":"actions","name":"apply"},
                "kind":"service-action",
                "file":"services/nursing.yaml",
                "pointer":"/map/steps/0/action"
            }],
            "mappings": [],
            "nativeParts": ["native/breg/nursing.yaml"],
            "coverageGaps": [],
            "checkGroups": ["workspace-v1"]
        }
    })
}

fn binary_native_snapshot_request(revision: &str) -> Value {
    let mut request = snapshot_request(revision);
    request["files"][2] = json!({
        "path":"native/breg/nursing.yaml",
        "state":"native",
        "sha256":"ea5dbf9596d187e9500f23e9a680109475341cf4e81f7e043f7d97152c10772f",
        "bytesBase64":"/wA="
    });
    request
}

fn large_snapshot_request() -> Value {
    let text = "x".repeat(4 * 1024 * 1024);
    json!({
        "apiVersion":API_VERSION,
        "operation":"analyze",
        "workspaceBinding":"workspace:test",
        "revision":"cancellable",
        "files":[file("large.txt","document",&text)],
        "facts":{"definitions":[],"mentions":[],"mappings":[],"nativeParts":[],"coverageGaps":[],"checkGroups":[]}
    })
}

fn authorization(after: Value) -> Value {
    json!({
        "status":"ready",
        "after":after,
        "uriBindings":[
            {"path":"actions/apply.yaml","uri":ACTION_URI},
            {"path":"services/nursing.yaml","uri":SERVICE_URI},
            {"path":"native/breg/nursing.yaml","uri":NATIVE_URI}
        ]
    })
}

fn authorization_with_before(after: Value, before: Value) -> Value {
    let mut value = authorization(after);
    value["before"] = before;
    value
}

fn authorized_query(id: u64, authorization: Value, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"registryStudio/authorizedQuery",
        "params":{"authorization":authorization,"request":{"method":method,"params":params}}
    })
}

fn file(path: &str, state: &str, text: &str) -> Value {
    let sha256 = Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    json!({
        "path":path,
        "state":state,
        "sha256":sha256,
        "bytesBase64":BASE64.encode(text)
    })
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

fn position(source: &str, occurrence: &str, token: &str) -> Value {
    let start = source.find(occurrence).expect("occurrence exists")
        + occurrence.find(token).expect("token exists");
    lsp_position(source, start)
}

fn position_end(source: &str, occurrence: &str, token: &str) -> Value {
    let start = source.find(occurrence).expect("occurrence exists")
        + occurrence.find(token).expect("token exists");
    lsp_position(source, start + token.len())
}

fn lsp_position(source: &str, byte: usize) -> Value {
    let prefix = &source[..byte];
    let line = prefix.bytes().filter(|value| *value == b'\n').count();
    let line_text = prefix.rsplit_once('\n').map_or(prefix, |(_, line)| line);
    json!({"line":line,"character":line_text.encode_utf16().count()})
}

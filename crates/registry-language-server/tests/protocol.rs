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

fn receive_method(stdout: &mut BufReader<ChildStdout>, method: &str) -> Value {
    for _ in 0..50 {
        let message = receive(stdout);
        if message.get("method").and_then(Value::as_str) == Some(method) {
            return message;
        }
    }
    panic!("language server did not send {method}");
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
    let manifest_uri = Uri::from_file_path(&manifest_path).unwrap().to_string();
    let integration_path = project
        .path()
        .join("integrations/people/integration.yaml")
        .canonicalize()
        .unwrap();
    let integration_uri = Uri::from_file_path(&integration_path).unwrap().to_string();

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
                "capabilities": {
                    "workspace": {
                        "didChangeWatchedFiles": { "dynamicRegistration": true }
                    }
                },
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
    let registration = receive(&mut stdout);
    assert_eq!(
        registration.get("method").and_then(Value::as_str),
        Some("client/registerCapability")
    );
    assert_eq!(
        registration
            .pointer("/params/registrations/0/method")
            .and_then(Value::as_str),
        Some("workspace/didChangeWatchedFiles")
    );
    assert_eq!(
        registration
            .pointer("/params/registrations/0/registerOptions/watchers/0/globPattern")
            .and_then(Value::as_str),
        Some("**/*.yaml")
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": registration.get("id").unwrap(),
            "result": null
        }),
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

    let changed_manifest = fs::read_to_string(&manifest_path)
        .unwrap()
        .replace("registry: { id: demo }", "registry: { id: external-demo }");
    fs::write(&manifest_path, changed_manifest).unwrap();
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWatchedFiles",
            "params": {
                "changes": [{ "uri": manifest_uri, "type": 2 }]
            }
        }),
    );
    let mut observed_external_change = false;
    for id in 5..15 {
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "workspace/symbol",
                "params": { "query": "external-demo" }
            }),
        );
        let reloaded_symbols = receive_response(&mut stdout, id);
        if reloaded_symbols
            .pointer("/result/0/name")
            .and_then(Value::as_str)
            == Some("external-demo")
        {
            observed_external_change = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(observed_external_change);

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 15, "method": "shutdown", "params": null }),
    );
    receive_response(&mut stdout, 15);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn reports_initial_and_lazy_project_load_failures_over_lsp() {
    for lazy in [false, true] {
        let project = TempDir::new().unwrap();
        let manifest = project.path().join("registry-stack.yaml");
        if !lazy {
            fs::write(&manifest, [0xff, 0xfe]).unwrap();
        }
        let root_uri = Uri::from_file_path(project.path()).unwrap().to_string();
        let manifest_uri = Uri::from_file_path(&manifest).unwrap().to_string();
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
                    "workspaceFolders": [{ "uri": root_uri, "name": "broken" }]
                }
            }),
        );
        receive_response(&mut stdout, 1);
        send(
            &mut stdin,
            json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
        );

        if lazy {
            let initial_log = receive_method(&mut stdout, "window/logMessage");
            assert_eq!(
                initial_log
                    .pointer("/params/message")
                    .and_then(Value::as_str),
                Some("No registry-stack.yaml project found in the workspace")
            );
            fs::write(&manifest, [0xff, 0xfe]).unwrap();
            send(
                &mut stdin,
                json!({
                    "jsonrpc": "2.0",
                    "method": "textDocument/didOpen",
                    "params": {
                        "textDocument": {
                            "uri": manifest_uri,
                            "languageId": "yaml",
                            "version": 1,
                            "text": "version: 1\nregistry: { id: unsaved }\nservices: {}\n"
                        }
                    }
                }),
            );
        }

        let error_log = receive_method(&mut stdout, "window/logMessage");
        assert_eq!(
            error_log.pointer("/params/type").and_then(Value::as_i64),
            Some(1),
            "{error_log}"
        );
        let message = error_log
            .pointer("/params/message")
            .and_then(Value::as_str)
            .unwrap();
        assert!(message.starts_with("Could not index Registry Stack project:"));
        assert!(!message.contains("No registry-stack.yaml project found"));
        assert!(
            message.len() <= 560,
            "load error was not bounded: {message}"
        );

        send(
            &mut stdin,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": null }),
        );
        receive_response(&mut stdout, 2);
        send(
            &mut stdin,
            json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
        );
        drop(stdin);
        assert!(child.wait().unwrap().success());
    }
}

#[test]
fn publishes_malformed_project_document_diagnostics() {
    let project = TempDir::new().unwrap();
    let manifest = project.path().join("registry-stack.yaml");
    fs::write(&manifest, "registry: [\n").unwrap();
    let root_uri = Uri::from_file_path(project.path()).unwrap().to_string();
    let manifest_uri = Uri::from_file_path(manifest.canonicalize().unwrap())
        .unwrap()
        .to_string();
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
                "workspaceFolders": [{ "uri": root_uri, "name": "malformed" }]
            }
        }),
    );
    receive_response(&mut stdout, 1);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );
    let diagnostics = receive_method(&mut stdout, "textDocument/publishDiagnostics");
    assert_eq!(
        diagnostics.pointer("/params/uri").and_then(Value::as_str),
        Some(manifest_uri.as_str())
    );
    assert!(diagnostics
        .pointer("/params/diagnostics")
        .and_then(Value::as_array)
        .is_some_and(|diagnostics| diagnostics.iter().any(|diagnostic| diagnostic
            .pointer("/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("Invalid YAML syntax")))));

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": null }),
    );
    receive_response(&mut stdout, 2);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn did_save_only_indexes_included_text_and_never_reads_uri_paths() {
    use std::{
        fs::FileTimes,
        os::unix::fs::symlink,
        time::{Duration, UNIX_EPOCH},
    };

    fn reset_access_time(path: &std::path::Path) -> std::time::SystemTime {
        let old = UNIX_EPOCH + Duration::from_secs(24 * 60 * 60);
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(FileTimes::new().set_accessed(old))
            .unwrap();
        fs::metadata(path).unwrap().accessed().unwrap()
    }

    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("registry-stack.yaml"),
        "version: 1\nregistry: { id: initial }\nservices: {}\n",
    )
    .unwrap();
    fs::create_dir(project.path().join("entities")).unwrap();

    let outside = TempDir::new().unwrap();
    let arbitrary_outside = outside.path().join("arbitrary.yaml");
    fs::write(&arbitrary_outside, "id: outside-save-content\n").unwrap();
    let symlink_target = outside.path().join("symlink-target.yaml");
    fs::write(&symlink_target, "id: symlink-save-content\n").unwrap();
    let symlink_path = project.path().join("entities/linked.yaml");
    symlink(&symlink_target, &symlink_path).unwrap();

    let oversized_path = project.path().join("entities/oversized.yaml");
    let mut oversized = b"id: oversized-save-content\n".to_vec();
    oversized.resize(1024 * 1024 + 1, b' ');
    fs::write(&oversized_path, oversized).unwrap();

    let root_uri = Uri::from_file_path(project.path()).unwrap().to_string();
    let manifest_path = project
        .path()
        .join("registry-stack.yaml")
        .canonicalize()
        .unwrap();
    let manifest_uri = Uri::from_file_path(&manifest_path).unwrap().to_string();
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
                "workspaceFolders": [{ "uri": root_uri, "name": "save-safety" }]
            }
        }),
    );
    let initialize = receive_response(&mut stdout, 1);
    assert_eq!(
        initialize
            .pointer("/result/capabilities/textDocumentSync/save/includeText")
            .and_then(Value::as_bool),
        Some(true)
    );
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );

    let outside_accessed = reset_access_time(&arbitrary_outside);
    let symlink_target_accessed = reset_access_time(&symlink_target);
    let oversized_accessed = reset_access_time(&oversized_path);
    for path in [&arbitrary_outside, &symlink_path, &oversized_path] {
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "method": "textDocument/didSave",
                "params": { "textDocument": { "uri": Uri::from_file_path(path).unwrap().to_string() } }
            }),
        );
    }
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": { "query": "save-content" }
        }),
    );
    let symbols = receive_response(&mut stdout, 2);
    assert_eq!(
        symbols.pointer("/result").and_then(Value::as_array),
        Some(&vec![])
    );
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        fs::metadata(&arbitrary_outside)
            .unwrap()
            .accessed()
            .unwrap(),
        outside_accessed,
        "didSave without text read an arbitrary outside URI"
    );
    assert_eq!(
        fs::metadata(&symlink_target).unwrap().accessed().unwrap(),
        symlink_target_accessed,
        "didSave without text followed a symlinked project-layout URI"
    );
    assert_eq!(
        fs::metadata(&oversized_path).unwrap().accessed().unwrap(),
        oversized_accessed,
        "didSave without text read an oversized project document"
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": manifest_uri,
                    "languageId": "yaml",
                    "version": 7,
                    "text": "version: 1\nregistry: { id: initial }\nservices: {}\n"
                }
            }
        }),
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {
                "textDocument": { "uri": manifest_uri },
                "text": "version: 1\nregistry: { id: included-save-content }\nservices: {}\n"
            }
        }),
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "workspace/symbol",
            "params": { "query": "included-save-content" }
        }),
    );
    let symbols = receive_response(&mut stdout, 3);
    assert_eq!(
        symbols.pointer("/result/0/name").and_then(Value::as_str),
        Some("included-save-content")
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": { "textDocument": { "uri": manifest_uri } }
        }),
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "workspace/symbol",
            "params": { "query": "initial" }
        }),
    );
    let reloaded = receive_response(&mut stdout, 4);
    assert_eq!(
        reloaded.pointer("/result/0/name").and_then(Value::as_str),
        Some("initial")
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

// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read, Write},
    process::{ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::Duration,
};

use serde_json::{json, Value};
use tempfile::TempDir;
use tower_lsp_server::ls_types::Uri;

/// How long a test waits for one more message before concluding the server has stopped
/// producing them. A regression that drops a notification should fail the waiting assertion
/// within this budget, not hang until the CI job's own timeout kills the run without a
/// diagnostic.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

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
    kind: consultation_api
    consultations:
      lookup: { integration: people }
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

/// Reads one framed LSP message from the server's stdout, or `None` once it closes stdout.
fn read_one_message(stdout: &mut BufReader<ChildStdout>) -> Option<Value> {
    let mut content_length = None;
    loop {
        let mut header = String::new();
        if stdout.read_line(&mut header).unwrap() == 0 {
            return None;
        }
        if header == "\r\n" {
            break;
        }
        if let Some(length) = header.strip_prefix("Content-Length:") {
            content_length = Some(length.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; content_length.expect("response has Content-Length")];
    stdout.read_exact(&mut body).unwrap();
    Some(serde_json::from_slice(&body).unwrap())
}

/// Reads framed LSP messages off the server's stdout on a background thread and forwards each
/// one to the returned channel. The blocking read stays confined to that thread, so a caller
/// waiting for a message that never arrives times out on `Receiver::recv_timeout` instead of
/// hanging on the pipe.
fn spawn_message_reader(stdout: ChildStdout) -> Receiver<Value> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        while let Some(message) = read_one_message(&mut reader) {
            if sender.send(message).is_err() {
                break; // the test dropped its receiver
            }
        }
    });
    receiver
}

/// Waits for one more message within [`MESSAGE_TIMEOUT`], panicking with a diagnosis instead of
/// blocking forever when the server has stopped producing them.
fn receive(messages: &Receiver<Value>) -> Value {
    receive_within(messages, MESSAGE_TIMEOUT)
}

/// [`receive`] with an explicit deadline, so the timeout itself can be exercised on a short
/// budget instead of waiting out [`MESSAGE_TIMEOUT`] for real.
fn receive_within(messages: &Receiver<Value>, timeout: Duration) -> Value {
    match messages.recv_timeout(timeout) {
        Ok(message) => message,
        Err(RecvTimeoutError::Timeout) => panic!("language server sent nothing for {timeout:?}"),
        Err(RecvTimeoutError::Disconnected) => panic!("language server closed stdout"),
    }
}

fn receive_response(messages: &Receiver<Value>, id: i64) -> Value {
    let mut others = Vec::new();
    loop {
        let message = receive(messages);
        if message.get("id").and_then(Value::as_i64) == Some(id) {
            return message;
        }
        others.push(message);
        assert!(
            others.len() < 50,
            "language server did not return response {id}; received instead: {others:?}"
        );
    }
}

fn receive_method(messages: &Receiver<Value>, method: &str) -> Value {
    let mut others = Vec::new();
    loop {
        let message = receive(messages);
        if message.get("method").and_then(Value::as_str) == Some(method) {
            return message;
        }
        others.push(message);
        assert!(
            others.len() < 50,
            "language server did not send {method}; received instead: {others:?}"
        );
    }
}

/// A regression that stops the server from ever sending an awaited notification must fail this
/// wait within a bounded deadline, not hang until the CI job's own timeout kills the run without
/// a diagnostic. This exercises the deadline on a short budget, on a channel that will never
/// produce anything, instead of waiting out the real `MESSAGE_TIMEOUT` used against a live server.
#[test]
fn receive_times_out_instead_of_hanging_when_nothing_arrives() {
    let (sender, messages) = mpsc::channel::<Value>();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        receive_within(&messages, Duration::from_millis(200))
    }))
    .expect_err("a message that never arrives is a panic, not a hang");
    drop(sender); // held open so the channel times out rather than disconnecting
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(
        message.contains("sent nothing"),
        "expected a timeout panic, got: {message}"
    );
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
    let stdout = spawn_message_reader(child.stdout.take().unwrap());

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
    let initialize = receive_response(&stdout, 1);
    assert_eq!(
        initialize.pointer("/result/capabilities/definitionProvider"),
        Some(&Value::Bool(true))
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );
    let registration = receive(&stdout);
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
    // Every authored extension gets its own glob and so does every directory a source's artifacts
    // sit in, so a watched-file event fires for a Relay project document, an Evidence derivation,
    // and a schema written as JSON alike; a glob lost here is a family of file the server would
    // stop hearing about.
    let watched_globs = registration
        .pointer("/params/registrations/0/registerOptions/watchers")
        .and_then(Value::as_array)
        .expect("the registration carries a watcher list")
        .iter()
        .map(|watcher| {
            watcher
                .pointer("/globPattern")
                .and_then(Value::as_str)
                .expect("a watcher names its glob pattern")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        watched_globs,
        BTreeSet::from([
            "**/*.yaml".to_owned(),
            "**/*.rhai".to_owned(),
            "**/adapters/*".to_owned(),
            "**/schemas/*".to_owned(),
        ])
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": registration.get("id").unwrap(),
            "result": null
        }),
    );
    let mut published_manifest_diagnostics = false;
    for _ in 0..3 {
        let notification = receive(&stdout);
        if notification.get("method").and_then(Value::as_str)
            == Some("textDocument/publishDiagnostics")
            && notification.pointer("/params/uri").and_then(Value::as_str)
                == Some(manifest_uri.as_str())
        {
            published_manifest_diagnostics = notification
                .pointer("/params/diagnostics")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty);
        }
    }
    assert!(published_manifest_diagnostics);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/definition",
            "params": {
                "textDocument": { "uri": manifest_uri },
                "position": { "line": 8, "character": 31 }
            }
        }),
    );
    let definition = receive_response(&stdout, 2);
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
    let references = receive_response(&stdout, 3);
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
            "params": { "query": "lookup" }
        }),
    );
    let symbols = receive_response(&stdout, 4);
    assert_eq!(
        symbols.pointer("/result/0/name").and_then(Value::as_str),
        Some("lookup")
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
        let reloaded_symbols = receive_response(&stdout, id);
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
    receive_response(&stdout, 15);
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
        let stdout = spawn_message_reader(child.stdout.take().unwrap());

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
        receive_response(&stdout, 1);
        send(
            &mut stdin,
            json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
        );

        if lazy {
            let initial_log = receive_method(&stdout, "window/logMessage");
            assert_eq!(
                initial_log
                    .pointer("/params/message")
                    .and_then(Value::as_str),
                Some("No Relay or Evidence project found in the workspace")
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

        let error_log = receive_method(&stdout, "window/logMessage");
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
        assert!(!message.contains("No Relay or Evidence project found"));
        assert!(
            message.len() <= 560,
            "load error was not bounded: {message}"
        );

        send(
            &mut stdin,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": null }),
        );
        receive_response(&stdout, 2);
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
    let stdout = spawn_message_reader(child.stdout.take().unwrap());

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
    receive_response(&stdout, 1);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );
    let diagnostics = receive_method(&stdout, "textDocument/publishDiagnostics");
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
    receive_response(&stdout, 2);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

/// Two projects of different families, each with a document that stops parsing, in one session. A
/// reader has to be able to tell which tool is reporting, so each diagnostic carries the name of
/// the family that produced it.
#[test]
fn diagnostics_name_the_family_that_produced_them() {
    use std::collections::BTreeMap;

    use registry_evidence_authoring::{
        layout::QUESTIONS_DIRECTORY,
        marker::{default_project_marker_document, PROJECT_MARKER_FILE},
    };

    let workspace = TempDir::new().unwrap();
    let relay = workspace.path().join("relay");
    let evidence = workspace.path().join("evidence");
    fs::create_dir_all(&relay).unwrap();
    fs::create_dir_all(evidence.join(QUESTIONS_DIRECTORY)).unwrap();
    fs::write(relay.join("registry-stack.yaml"), "registry: [\n").unwrap();
    fs::write(
        evidence.join(PROJECT_MARKER_FILE),
        default_project_marker_document(),
    )
    .unwrap();
    let question = evidence.join(QUESTIONS_DIRECTORY).join("adult-status.yaml");
    fs::write(&question, "id: [\n").unwrap();

    let uri_of = |path: &std::path::Path| {
        Uri::from_file_path(path.canonicalize().unwrap())
            .unwrap()
            .to_string()
    };
    let manifest_uri = uri_of(&relay.join("registry-stack.yaml"));
    let question_uri = uri_of(&question);
    let relay_folder_uri = uri_of(&relay);
    let evidence_folder_uri = uri_of(&evidence);

    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-language-server"))
        .current_dir(workspace.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = spawn_message_reader(child.stdout.take().unwrap());

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": {},
                "workspaceFolders": [
                    { "uri": relay_folder_uri, "name": "relay" },
                    { "uri": evidence_folder_uri, "name": "evidence" }
                ]
            }
        }),
    );
    receive_response(&stdout, 1);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );

    let mut sources = BTreeMap::new();
    for _ in 0..50 {
        let message = receive(&stdout);
        if message.get("method").and_then(Value::as_str) != Some("textDocument/publishDiagnostics")
        {
            continue;
        }
        let uri = message
            .pointer("/params/uri")
            .and_then(Value::as_str)
            .expect("a published document names its URI")
            .to_owned();
        for diagnostic in message
            .pointer("/params/diagnostics")
            .and_then(Value::as_array)
            .expect("a published document carries a diagnostics array")
        {
            if diagnostic
                .pointer("/message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains("Invalid YAML syntax"))
            {
                sources.insert(
                    uri.clone(),
                    diagnostic
                        .pointer("/source")
                        .and_then(Value::as_str)
                        .expect("a diagnostic names its source")
                        .to_owned(),
                );
            }
        }
        if sources.len() == 2 {
            break;
        }
    }

    assert_eq!(
        sources.get(&manifest_uri).map(String::as_str),
        Some("registry-stack"),
        "{sources:?}"
    );
    assert_eq!(
        sources.get(&question_uri).map(String::as_str),
        Some("evidence"),
        "{sources:?}"
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": null }),
    );
    receive_response(&stdout, 2);
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
    let stdout = spawn_message_reader(child.stdout.take().unwrap());

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
    let initialize = receive_response(&stdout, 1);
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
    let symbols = receive_response(&stdout, 2);
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
    let symbols = receive_response(&stdout, 3);
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
    let reloaded = receive_response(&stdout, 4);
    assert_eq!(
        reloaded.pointer("/result/0/name").and_then(Value::as_str),
        Some("initial")
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 6, "method": "shutdown", "params": null }),
    );
    receive_response(&stdout, 6);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn serves_untitled_and_rootless_documents_without_error() {
    let project = write_project();
    let root_uri = Uri::from_file_path(project.path()).unwrap().to_string();
    let elsewhere = TempDir::new().unwrap();
    let rootless = elsewhere.path().join("notes.yaml");
    fs::write(&rootless, "version: 1\nid: rootless\n").unwrap();
    let rootless_uri = Uri::from_file_path(rootless.canonicalize().unwrap())
        .unwrap()
        .to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-language-server"))
        .current_dir(project.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = spawn_message_reader(child.stdout.take().unwrap());

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
    receive_response(&stdout, 1);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );

    // An `untitled:` buffer and a `zipfile:` document name nothing on this filesystem, so the
    // server declines them outright; a real file outside every project is served with an empty
    // answer instead.
    for (id, uri, answers) in [
        (2, "untitled:Untitled-1", false),
        (3, "zipfile:///archive.zip::/registry-stack.yaml", false),
        (4, rootless_uri.as_str(), true),
    ] {
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": uri,
                        "languageId": "yaml",
                        "version": 1,
                        "text": "version: 1\nid: scratch\n"
                    }
                }
            }),
        );
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "textDocument/documentSymbol",
                "params": { "textDocument": { "uri": uri } }
            }),
        );

        let mut symbols = None;
        for _ in 0..50 {
            let message = receive(&stdout);
            if message.get("id").and_then(Value::as_i64) == Some(id) {
                symbols = Some(message);
                break;
            }
            assert_ne!(
                message.pointer("/params/type").and_then(Value::as_i64),
                Some(1),
                "{uri} logged an error: {message}"
            );
            assert_ne!(
                message.pointer("/params/uri").and_then(Value::as_str),
                Some(uri),
                "{uri} was published diagnostics: {message}"
            );
        }
        let symbols = symbols.expect("the server always answers a documentSymbol request");
        assert_eq!(
            symbols.pointer("/result").and_then(Value::as_array),
            answers.then_some(&vec![]),
            "{symbols}"
        );
    }

    // The project the client did open is still indexed.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "workspace/symbol",
            "params": { "query": "lookup" }
        }),
    );
    let indexed = receive_response(&stdout, 5);
    assert_eq!(
        indexed.pointer("/result/0/name").and_then(Value::as_str),
        Some("lookup")
    );

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 6, "method": "shutdown", "params": null }),
    );
    receive_response(&stdout, 6);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

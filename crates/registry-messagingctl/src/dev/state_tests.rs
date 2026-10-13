// SPDX-License-Identifier: Apache-2.0

use super::*;

fn current(owner: &str, state: &str, borrowed_issuer: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "apiVersion": DEV_STATE_API_VERSION,
        "kind": DEV_STATE_KIND,
        "owner": owner,
        "state": state,
        "containers": [],
        "detail": {},
        "borrowedIssuer": borrowed_issuer,
    }))
    .unwrap()
}

/// `current`, written one member to a line so every value has a position of
/// its own.
fn current_lines(owner: &str, state: &str, borrowed_issuer: Value) -> String {
    let record: Value = serde_json::from_slice(&current(owner, state, borrowed_issuer)).unwrap();
    serde_json::to_string_pretty(&record).unwrap()
}

/// The line and column of the first character of the value `text` gives the
/// member the pointer `path` ends in, whose key `text` writes once.
fn value_position(text: &str, path: &str) -> (Option<usize>, Option<usize>) {
    let key = format!("\"{}\": ", path.rsplit('/').next().unwrap());
    assert_eq!(text.matches(&key).count(), 1, "{path}");
    let start = text.find(&key).unwrap() + key.len();
    let line_start = text[..start].rfind('\n').map_or(0, |index| index + 1);
    (
        Some(text[..start].matches('\n').count() + 1),
        Some(start - line_start + 1),
    )
}

/// What `check_session_file` refuses `text` for: every diagnostic's code and
/// path, after requiring each to name `path` and its own value's position.
fn refused_members(path: &Path, text: &str) -> Vec<(String, String)> {
    fs::write(path, text).unwrap();
    let refusal = check_session_file(path).unwrap_err();
    assert_eq!(refusal.exit, DOMAIN_REFUSAL_EXIT);
    refusal
        .report
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            let source = diagnostic.source.as_ref().unwrap();
            assert_eq!(source.file, path.display().to_string());
            assert_eq!(
                (source.line, source.column),
                value_position(text, &diagnostic.path),
                "{}",
                diagnostic.path
            );
            assert!(
                !diagnostic.suggested_action.is_empty(),
                "{}",
                diagnostic.path
            );
            (diagnostic.code.clone(), diagnostic.path.clone())
        })
        .collect()
}

fn member(code: &str, path: &str) -> (String, String) {
    (code.to_owned(), path.to_owned())
}

const INVALID_BORROWED_ISSUER: &str = "messaging.dev-state.invalid-borrowed-issuer";

#[test]
fn offline_state_diagnostics_keep_the_given_file_and_member_positions() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("retained-session.json");
    let text = current_lines(
        "not-an-owner",
        "unknown",
        json!({
            "project": "relative",
            "bregctl": "relative",
            "issuer": "http://localhost:9000",
            "tokenEndpoint": "http://localhost:9000/token",
            "resource": "not-a-resource",
            "clients": {},
        }),
    );

    assert_eq!(
        refused_members(&path, &text),
        [
            member("messaging.dev-state.invalid-owner", "/owner"),
            member("messaging.dev-state.invalid-state", "/state"),
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/project"),
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/bregctl"),
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/issuer"),
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/tokenEndpoint"),
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/resource"),
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/clients"),
        ]
    );
}

/// A borrowed issuer binding `messagingctl` would write.
fn borrowed_issuer() -> Value {
    json!({
        "project": "/owner",
        "bregctl": "/bin/bregctl",
        "issuer": "http://127.0.0.1:8095",
        "tokenEndpoint": "http://127.0.0.1:8095/oauth2/token",
        "resource": "urn:registrystack:messaging:notices",
        "clients": {"case-system": {"principal": "case-system", "profile": "case-notices"}},
    })
}

#[test]
fn offline_state_diagnostics_name_each_invalid_borrowed_issuer_member() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("retained-session.json");
    let owner = uuid::Uuid::new_v4().simple().to_string();
    // The token endpoint is the one this issuer would publish, so the issuer
    // and the resource are the only members at fault.
    let mut binding = borrowed_issuer();
    binding["issuer"] = json!("http://localhost:9000");
    binding["tokenEndpoint"] = json!("http://localhost:9000/oauth2/token");
    binding["resource"] = json!("not-a-resource");
    let text = current_lines(&owner, "stopped", binding);

    assert_eq!(
        refused_members(&path, &text),
        [
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/issuer"),
            member(INVALID_BORROWED_ISSUER, "/borrowedIssuer/resource"),
        ]
    );
    let refusal = check_session_file(&path).unwrap_err();
    let diagnostics = refusal.report.diagnostics();
    assert_eq!(
        diagnostics[0].message,
        "the borrowed issuer is not one loopback origin of the form http://127.0.0.1:<port>"
    );
    assert_eq!(
        diagnostics[1].message,
        "the borrowed resource is not an absolute resource URI without credentials or fragment"
    );
    // Neither sentence repeats the value it refuses (CFG-SEC-3).
    for diagnostic in diagnostics {
        for value in ["localhost", "not-a-resource"] {
            assert!(!diagnostic.message.contains(value), "{}", diagnostic.path);
            assert!(
                !diagnostic.suggested_action.contains(value),
                "{}",
                diagnostic.path
            );
        }
    }
}

/// The members of `binding` that `Binding::invalid_members` names.
fn invalid_members(binding: Value) -> Vec<&'static str> {
    serde_json::from_value::<borrowed::Binding>(binding)
        .unwrap()
        .invalid_members()
        .iter()
        .map(|invalid| invalid.member)
        .collect()
}

#[test]
fn a_borrowed_issuer_member_is_judged_on_its_own() {
    assert!(invalid_members(borrowed_issuer()).is_empty());

    let mut endpoint = borrowed_issuer();
    endpoint["tokenEndpoint"] = json!("http://127.0.0.1:8095/token");
    assert_eq!(invalid_members(endpoint), ["tokenEndpoint"]);

    // A port no listener can hold and a second spelling of a port are not the
    // exact origin. The token endpoint is judged against the issuer as
    // written, so it is at fault only when it does not follow that issuer.
    for issuer in ["http://127.0.0.1:0", "http://127.0.0.1:08095"] {
        let mut binding = borrowed_issuer();
        binding["issuer"] = json!(issuer);
        assert_eq!(
            invalid_members(binding.clone()),
            ["issuer", "tokenEndpoint"],
            "{issuer}"
        );
        binding["tokenEndpoint"] = json!(format!("{issuer}/oauth2/token"));
        assert_eq!(invalid_members(binding), ["issuer"], "{issuer}");
    }

    // An empty map and a name that cannot be a file name are both reported at
    // the map, each with its own sentence.
    let message = |binding: Value| {
        let binding: borrowed::Binding = serde_json::from_value(binding).unwrap();
        let invalid = binding.invalid_members();
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].member, "clients");
        invalid[0].message
    };
    let mut empty = borrowed_issuer();
    empty["clients"] = json!({});
    let mut hidden = borrowed_issuer();
    let pin = hidden["clients"]["case-system"].clone();
    hidden["clients"] = json!({".hidden": pin});
    assert_eq!(
        message(empty),
        "the borrowed issuer binding names no client"
    );
    assert_eq!(
        message(hidden),
        "a borrowed client name is not a bounded identifier of letters, digits, hyphens, \
         underscores or dots"
    );
}

#[test]
fn cleanup_accepts_only_typed_current_or_uuid_legacy_owners() {
    let temporary = tempfile::tempdir().unwrap();
    let file = temporary.path().join("session.json");
    let owner = uuid::Uuid::new_v4().simple().to_string();

    let current = current(&owner, "stopped", Value::Null);
    // Optional values are represented by an absent member in the shared
    // configuration reader.
    let mut current_value: Value = serde_json::from_slice(&current).unwrap();
    current_value
        .as_object_mut()
        .unwrap()
        .remove("borrowedIssuer");
    let current = serde_json::to_vec(&current_value).unwrap();
    assert_eq!(previous_owner(&file, &current).unwrap(), owner);

    let legacy = serde_json::to_vec(&json!({"owner": owner, "state": "stopped"})).unwrap();
    assert_eq!(previous_owner(&file, &legacy).unwrap(), owner);

    let one_envelope_member = serde_json::to_vec(&json!({
        "apiVersion": DEV_STATE_API_VERSION,
        "owner": owner,
    }))
    .unwrap();
    assert!(previous_owner(&file, &one_envelope_member).is_err());

    let future = serde_json::to_vec(&json!({
        "apiVersion": "id.registrystack.org/formats/messaging/dev-state/v2",
        "kind": DEV_STATE_KIND,
        "owner": owner,
    }))
    .unwrap();
    assert!(previous_owner(&file, &future).is_err());

    let invalid_legacy = serde_json::to_vec(&json!({"owner": "not-a-uuid"})).unwrap();
    assert!(previous_owner(&file, &invalid_legacy).is_err());
}

/// A session record `messagingctl` would write, padded with trailing
/// whitespace to exactly `length` bytes.
fn padded(length: usize) -> Vec<u8> {
    let owner = uuid::Uuid::new_v4().simple().to_string();
    let mut value: Value =
        serde_json::from_slice(&current(&owner, "stopped", Value::Null)).unwrap();
    value.as_object_mut().unwrap().remove("borrowedIssuer");
    let mut bytes = serde_json::to_vec(&value).unwrap();
    assert!(bytes.len() <= length);
    bytes.resize(length, b' ');
    bytes
}

#[test]
fn offline_state_check_accepts_a_file_of_exactly_the_shared_bound() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("session.json");
    fs::write(
        &path,
        padded(registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES),
    )
    .unwrap();

    let report = check_session_file(&path).unwrap();
    assert!(!report.has_errors());
}

#[test]
fn offline_state_check_refuses_a_file_above_the_shared_bound_with_the_shared_code() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("session.json");
    fs::write(
        &path,
        padded(registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES + 1),
    )
    .unwrap();

    let refusal = check_session_file(&path).unwrap_err();
    assert_eq!(refusal.exit, DOMAIN_REFUSAL_EXIT);
    assert_eq!(
        refusal
            .report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>(),
        ["yaml.too-large"]
    );
}

#[test]
fn a_start_reads_back_a_session_record_of_exactly_the_shared_bound() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("dev");
    private::directory(&root).unwrap();
    private::create(
        &root.join("session.json"),
        &padded(registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES),
    )
    .unwrap();

    assert_eq!(read_session(&root).unwrap().state, "stopped");
}

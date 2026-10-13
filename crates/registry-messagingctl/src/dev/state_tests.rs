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

#[test]
fn offline_state_diagnostics_keep_the_given_file_and_member_positions() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("retained-session.json");
    fs::write(
        &path,
        current(
            "not-an-owner",
            "unknown",
            json!({
                "project": "relative",
                "bregctl": "relative",
                "issuer": "http://localhost:9000",
                "tokenEndpoint": "http://localhost:9000/oauth2/token",
                "resource": "not-a-resource",
                "clients": {},
            }),
        ),
    )
    .unwrap();

    let refusal = check_session_file(&path).unwrap_err();
    assert_eq!(refusal.exit, DOMAIN_REFUSAL_EXIT);
    let diagnostics = refusal.report.diagnostics();
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>(),
        [
            ("messaging.dev-state.invalid-owner", "/owner"),
            ("messaging.dev-state.invalid-state", "/state"),
            (
                "messaging.dev-state.invalid-borrowed-issuer",
                "/borrowedIssuer",
            ),
        ]
    );
    assert!(diagnostics.iter().all(|diagnostic| {
        diagnostic.source.as_ref().is_some_and(|source| {
            source.file == path.display().to_string()
                && source.line.is_some()
                && source.column.is_some()
        })
    }));
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

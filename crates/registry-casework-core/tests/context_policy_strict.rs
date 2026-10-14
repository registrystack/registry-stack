// SPDX-License-Identifier: Apache-2.0
//! Both context modes have a closed authoring shape, including the submitted
//! mode that remains a public unit variant.

use registry_casework_core::{CaseworkProject, ContentDigest, ReviewContextPolicy};
use serde_json::json;

const STANDALONE: &str =
    include_str!("../../../products/casework/examples/standalone-decision/casework.yaml");

#[test]
fn submitted_context_refuses_unknown_members_in_json_and_located_yaml() {
    assert!(serde_json::from_value::<ReviewContextPolicy>(
        json!({"mode":"submitted","conformanceUnknown":42})
    )
    .is_err());

    let changed = STANDALONE.replacen(
        "context: {mode: submitted}",
        "context: {mode: submitted, conformanceUnknown: 42}",
        1,
    );
    assert_ne!(changed, STANDALONE);
    let report = CaseworkProject::read("casework.yaml", changed.as_bytes()).unwrap_err();
    let finding = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.path == "/reviewPolicies/0/context/conformanceUnknown")
        .expect("the unknown context member has its own location");
    assert_eq!(finding.code, "config.unknown-key");
    assert!(finding.source.as_ref().and_then(|site| site.line).is_some());
    assert!(finding
        .source
        .as_ref()
        .and_then(|site| site.column)
        .is_some());
}

#[test]
fn canonical_context_modes_keep_their_wire_shape() {
    let submitted: ReviewContextPolicy =
        serde_json::from_value(json!({"mode":"submitted"})).unwrap();
    assert_eq!(submitted, ReviewContextPolicy::Submitted);
    assert_eq!(
        serde_json::to_value(submitted).unwrap(),
        json!({"mode":"submitted"})
    );
    CaseworkProject::read("casework.yaml", STANDALONE.as_bytes()).unwrap();

    let contract = json!({
        "id":"urn:registry:review-context:facility-address",
        "revision":ContentDigest::for_bytes(b"revision"),
        "schemaDigest":ContentDigest::for_bytes(b"schema")
    });
    let source: ReviewContextPolicy = serde_json::from_value(json!({
        "mode":"current-source", "provider":"facility-context", "contract":contract
    }))
    .unwrap();
    assert!(matches!(source, ReviewContextPolicy::CurrentSource { .. }));
    assert_eq!(
        serde_json::to_value(source).unwrap()["mode"],
        "current-source"
    );
    assert!(serde_json::from_value::<ReviewContextPolicy>(json!({
        "mode":"current-source", "provider":"facility-context",
        "contract":contract, "conformanceUnknown":42
    }))
    .is_err());
}

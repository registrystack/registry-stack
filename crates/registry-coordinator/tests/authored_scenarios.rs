// SPDX-License-Identifier: Apache-2.0
use registry_coordinator::scenarios::{self, Reply};
use serde_json::json;

fn source(reply: &str, extra_expect: &str) -> String {
    format!(
        "apiVersion: {}\nkind: {}\ncases:\n- id: one-case\n  admittedAt: '2026-10-09T09:00:00Z'\n  input: {{nested: [null, {{optional: null}}]}}\n  replies:\n    call-one:\n    - {reply}\n  expect:\n    path: [call-one]\n    state: uncertain\n{extra_expect}",
        scenarios::API_VERSION, scenarios::KIND
    )
}

#[test]
fn authored_scenarios_decode_tagged_replies_and_preserve_foreign_nulls() {
    let document = scenarios::decode(
        &source(
            "{type: success, value: {nested: [null]}}",
            "    output: null\n",
        ),
        "scenarios.yaml",
    )
    .unwrap();
    let case = &document.cases[0];
    assert_eq!(case.input, json!({"nested": [null, {"optional": null}]}));
    assert!(
        matches!(&case.replies["call-one"][0], Reply::Success {success} if success == &json!({"nested": [null]}))
    );
    assert_eq!(case.expect.output, Some(serde_json::Value::Null));
    assert!(case.expect.skip_outcome_check);

    for reply in [
        "{type: retryable, code: transport-unavailable}",
        "{type: refused, code: credential-refused}",
        "{type: uncertain, code: transport-uncertain}",
        "{type: receipt-expired}",
    ] {
        scenarios::decode(
            &source(reply, "    outcome: {type: none}\n"),
            "scenarios.yaml",
        )
        .unwrap();
    }
}

#[test]
fn authored_outcome_omission_and_explicit_absence_are_distinct() {
    let omitted =
        scenarios::decode(&source("{type: receipt-expired}", ""), "scenarios.yaml").unwrap();
    let absent = scenarios::decode(
        &source("{type: receipt-expired}", "    outcome: {type: none}\n"),
        "scenarios.yaml",
    )
    .unwrap();
    let named = scenarios::decode(
        &source(
            "{type: receipt-expired}",
            "    outcome: {type: named, value: accepted}\n",
        ),
        "scenarios.yaml",
    )
    .unwrap();
    assert!(omitted.cases[0].expect.skip_outcome_check);
    assert!(!absent.cases[0].expect.skip_outcome_check);
    assert!(absent.cases[0].expect.outcome.is_none());
    assert!(!named.cases[0].expect.skip_outcome_check);
    assert_eq!(named.cases[0].expect.outcome.as_deref(), Some("accepted"));
}

#[test]
fn authored_scenarios_refuse_legacy_unions_unknown_members_and_substitution() {
    for (text, code, pointer) in [
        (
            source("{success: {}}", ""),
            "config.missing-key",
            "/cases/0/replies/call-one/0",
        ),
        (
            source("{type: receipt-expired, receiptExpired: true}", ""),
            "config.unknown-key",
            "/cases/0/replies/call-one/0/receiptExpired",
        ),
        (
            source("{type: success, value: {nested: '${PRIVATE_VALUE}'}}", ""),
            "config.substitution-not-allowed",
            "/cases/0/replies/call-one/0/value/nested",
        ),
        (
            source("{type: receipt-expired}", "")
                .replace("path: [call-one]", "path: [call-one, call-one]"),
            "config.duplicate-item",
            "/cases/0/expect/path/1",
        ),
        (
            source("{type: receipt-expired}", "    outcome: null\n"),
            "config.null-value",
            "/cases/0/expect/outcome",
        ),
        (
            source("{type: receipt-expired}", "").replace("id: one-case", "id: Invalid"),
            "config.invalid-value",
            "/cases/0/id",
        ),
        (
            source("{type: receipt-expired}", "").replace("call-one:", "Invalid:"),
            "config.invalid-value",
            "/cases/0/replies/Invalid",
        ),
    ] {
        let error = scenarios::decode(&text, "private-scenarios.yaml")
            .err()
            .expect("must refuse");
        let finding = error
            .diagnostics
            .iter()
            .find(|finding| finding.code == code)
            .unwrap_or_else(|| panic!("{error}"));
        assert_eq!(finding.path, pointer);
        let place = finding.source.as_ref().unwrap();
        assert_eq!(place.file, "private-scenarios.yaml");
        assert!(place.line.is_some());
        assert!(!error.to_string().contains("PRIVATE_VALUE"));
    }
}

#[test]
fn authored_scenarios_refuse_aliases_duplicates_and_position_semantic_bounds() {
    for (text, code) in [
        (
            source("{type: success, value: &node {}}", ""),
            "yaml.anchor",
        ),
        (
            source("{type: success, value: {a: null, a: 1}}", ""),
            "yaml.duplicate-key",
        ),
        (source("{type: success, value: !!map {}}", ""), "yaml.tag"),
        (
            source(
                "{type: receipt-expired}",
                "    workflowElapsedSeconds: -1\n",
            ),
            "config.out-of-range",
        ),
        (
            source("{type: receipt-expired}", "")
                .replace("'2026-10-09T09:00:00Z'", "not-a-timestamp"),
            "coordinator.scenarios.invalid-timestamp",
        ),
        (
            format!(
                "apiVersion: {}\nkind: {}\ncases: []\n",
                scenarios::API_VERSION,
                scenarios::KIND
            ),
            "coordinator.scenarios.invalid-length",
        ),
    ] {
        let error = scenarios::decode(&text, "scenarios.yaml")
            .err()
            .expect("must refuse");
        assert!(
            error.diagnostics.iter().any(|finding| finding.code == code),
            "{error}"
        );
    }
    let text = source("{type: receipt-expired}", "");
    let case = text.split("cases:\n").nth(1).unwrap();
    let duplicate = format!("{text}{case}");
    let error = scenarios::decode(&duplicate, "scenarios.yaml")
        .err()
        .expect("duplicate ID must refuse");
    assert!(error
        .diagnostics
        .iter()
        .any(|finding| finding.code == "config.duplicate-id" && finding.path == "/cases/1/id"));
}

#[cfg(feature = "schema")]
#[test]
fn scenario_schema_keeps_foreign_payloads_and_closed_tagged_forms() {
    let schema: serde_json::Value =
        serde_json::from_str(&scenarios::scenario_schema().unwrap()).unwrap();
    assert_eq!(
        schema["properties"]["apiVersion"]["const"],
        scenarios::API_VERSION
    );
    assert_eq!(schema["properties"]["kind"]["const"], scenarios::KIND);
    assert_eq!(
        schema["$defs"]["AuthoredScenario"]["properties"]["input"]["x-registry-foreign"],
        "json"
    );
    assert_eq!(
        schema["$defs"]["AuthoredExpectation"]["properties"]["output"]["x-registry-foreign"],
        "json"
    );
    assert_eq!(
        schema["$defs"]["AuthoredScenario"]["properties"]["replies"]["maxProperties"],
        64
    );
    assert!(schema["$defs"]["AuthoredReply"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .all(|variant| variant["additionalProperties"] == false
            && variant["properties"]["type"]["const"].is_string()));
}

#[test]
fn scenario_file_uses_the_shared_capacity_without_relaxing_work_bounds() {
    // Comment padding changes file capacity only. It does not expand a payload,
    // graph, or synthetic reply list past its separate semantic bounds.
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("scenarios.yaml");
    let text = format!(
        "#{}\n{}",
        " harmless comment".repeat(17_000),
        source("{type: receipt-expired}", "")
    );
    assert!(text.len() > 262_144 && text.len() < 1_048_576);
    std::fs::write(&path, text).unwrap();
    let document = scenarios::load(&path).unwrap();
    assert_eq!(document.cases.len(), 1);
    assert!(matches!(
        &document.cases[0].replies["call-one"][0],
        Reply::ReceiptExpired {
            receipt_expired: true
        }
    ));
}

#[test]
fn scenario_file_encoding_refusal_comes_from_the_shared_reader() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("scenarios.yaml");
    std::fs::write(&path, b"\xff").unwrap();
    let error = scenarios::load(&path)
        .err()
        .expect("invalid UTF-8 must refuse");
    assert_eq!(error.code, "yaml.not-utf8");
    assert_eq!(
        error.diagnostics[0].source.as_ref().unwrap().file,
        path.display().to_string()
    );
}

#[test]
fn oversized_scenario_file_is_reported_by_the_shared_reader() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("scenarios.yaml");
    std::fs::write(
        &path,
        format!(
            "#{}\n{}",
            "x".repeat(1_048_576),
            source("{type: receipt-expired}", "")
        ),
    )
    .unwrap();
    let error = scenarios::load(&path).err().expect("oversized file");
    assert_eq!(error.code, "yaml.too-large");
    assert_eq!(
        error.diagnostics[0].source.as_ref().unwrap().file,
        path.display().to_string()
    );
}

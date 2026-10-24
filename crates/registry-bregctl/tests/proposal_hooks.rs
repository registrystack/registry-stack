// SPDX-License-Identifier: Apache-2.0
#[path = "../../registry-breg/tests/support/proposal_hooks_model.rs"]
mod model;
use serde_json::{json, Value};
use std::ffi::OsString;

fn run(arguments: Vec<OsString>) -> Value {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(arguments, &mut stdout, &mut stderr);
    assert_eq!(
        status,
        std::process::ExitCode::SUCCESS,
        "{}\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    serde_json::from_slice(&stdout).unwrap()
}

#[test]
fn native_observers_load_owned_assets_generate_schema_and_sample_the_real_transition() {
    let temporary = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temporary.path()).unwrap();
    std::fs::create_dir(root.join("hooks")).unwrap();
    let source = model::source(json!([
        model::url_hook(),
        model::local_hook("local", json!(["cancelled"]))
    ]));
    std::fs::write(
        root.join("registry.yaml"),
        serde_json::to_vec(&source).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("hooks/local.rhai"),
        b"fn handle(ctx) { #{answer: \"none\"} }",
    )
    .unwrap();
    let checked = run(vec![
        "bregctl".into(),
        "--format".into(),
        "json".into(),
        "check".into(),
        root.as_os_str().into(),
    ]);
    assert_eq!(checked["ok"], true);
    let output = root.join("generated");
    run(vec![
        "bregctl".into(),
        "--format".into(),
        "json".into(),
        "generate".into(),
        "schemas".into(),
        root.as_os_str().into(),
        "--output".into(),
        output.as_os_str().into(),
    ]);
    let schema_path = output.join(registry_breg::proposal_hooks::PROPOSAL_EVENT_SCHEMA_PATH);
    let schema: Value = serde_json::from_slice(&std::fs::read(schema_path).unwrap()).unwrap();
    assert_eq!(
        schema,
        registry_breg::proposal_hooks::proposal_event_schema()
    );
    let sample = run(vec![
        "bregctl".into(),
        "--format".into(),
        "json".into(),
        "hook".into(),
        "sample".into(),
        root.as_os_str().into(),
        "--event".into(),
        "local".into(),
    ]);
    assert_eq!(
        sample["request"]["headers"]["ce-type"],
        "proposal.cancelled"
    );
    assert_eq!(sample["request"]["body"]["data"]["transition"], "cancelled");
    assert_eq!(sample["request"]["body"]["data"]["state"], "cancelled");
    assert!(sample["request"]["body"]["data"].get("values").is_none());
}

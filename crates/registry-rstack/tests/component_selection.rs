use registry_rstack::{ComponentManifest, Selection};

fn sample() -> ComponentManifest {
    serde_json::from_str(
        r#"{
          "schema_version":"registry-stack.components.v1",
          "release":"v0.44.0",
          "launcher":{
            "linux-amd64":{"name":"rstack-v0.44.0-linux-amd64","size":8,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
          },
          "components":{
            "breg":{"entrypoint":"bregctl","dependencies":[],"platforms":{
              "linux-amd64":{"assets":[{"name":"bregctl-v0.44.0-linux-amd64","size":11,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"capabilities":{"tooling":true,"runtime":false}}
            }},
            "casework":{"entrypoint":"caseworkctl","dependencies":["breg"],"platforms":{
              "linux-amd64":{"assets":[{"name":"caseworkctl-v0.44.0-linux-amd64","size":12,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"capabilities":{"tooling":true,"runtime":false}}
            }},
            "scheduling":{"entrypoint":"schedulingctl","dependencies":[],"platforms":{
              "linux-amd64":{"assets":[{"name":"schedulingctl-v0.44.0-linux-amd64","size":13,"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}],"capabilities":{"tooling":true,"runtime":false}}
            }}
          }
        }"#,
    )
    .unwrap()
}

#[test]
fn selection_adds_required_dependencies_and_counts_exact_assets() {
    let manifest = sample();
    let selected = manifest
        .select("linux-amd64", Selection::Names(vec!["casework".into()]))
        .unwrap();
    assert_eq!(selected.components, vec!["breg", "casework"]);
    assert_eq!(selected.download_bytes, 8 + 11 + 12);
}

#[test]
fn unavailable_mixed_selection_refuses_whole_plan() {
    let manifest = sample();
    let error = manifest
        .select(
            "macos-arm64",
            Selection::Names(vec!["casework".into(), "scheduling".into()]),
        )
        .unwrap_err();
    assert!(error.to_string().contains("unavailable"));
    let error = manifest
        .select(
            "linux-amd64",
            Selection::Names(vec!["casework".into(), "unknown".into()]),
        )
        .unwrap_err();
    assert!(error.to_string().contains("unknown component"));
}

#[test]
fn all_selects_only_baselines_available_on_platform() {
    let manifest = sample();
    let selected = manifest.select("linux-amd64", Selection::All).unwrap();
    assert_eq!(selected.components, vec!["breg", "casework", "scheduling"]);
    assert_eq!(selected.download_bytes, 8 + 11 + 12 + 13);
}

#[test]
fn unknown_fields_and_invalid_digest_are_refused() {
    let value = serde_json::json!({
        "schema_version":"registry-stack.components.v1",
        "release":"v0.44.0",
        "launcher":{"linux-amd64":{"name":"rstack","size":8,"sha256":"bad"}},
        "components":{}
    });
    let manifest: ComponentManifest = serde_json::from_value(value.clone()).unwrap();
    assert!(manifest.validate().is_err());
    let mut wrong = value;
    wrong["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ComponentManifest>(wrong).is_err());
}

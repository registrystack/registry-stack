//! Public fixture checks retain authored locations and reject vacuous proofs.
use super::*;
use registry_platform_yaml::Report;

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = crate::canonical_tempdir();
    let project = directory.path().join("review");
    crate::project::init(&project, "standalone-decision").unwrap();
    let fixture = project.join("fixtures/standalone-decision.yaml");
    (directory, project, fixture)
}
fn fixture_value(path: &std::path::Path) -> Value {
    registry_platform_yaml::Reader::new("fixture.yaml")
        .scan(&std::fs::read(path).unwrap())
        .unwrap()
        .unwrap()
        .to_json_value()
}
#[test]
fn fixture_test_option_and_init_schema_are_executable() {
    let (_directory, project, fixture) = setup();
    assert!(std::fs::read_to_string(&fixture)
        .unwrap()
        .starts_with("# yaml-language-server: $schema=../.casework/schemas/fixture.schema.json\n"));
    assert!(project
        .join(".casework/schemas/fixture.schema.json")
        .is_file());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = main_entry_from(
        [
            OsString::from("caseworkctl"),
            OsString::from("--format"),
            OsString::from("json"),
            OsString::from("test"),
            project.as_os_str().to_owned(),
            OsString::from("--deny-warnings"),
        ],
        &mut out,
        &mut err,
    );
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    assert!(err.is_empty());
    let report: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["data"]["proofBoundary"], "offline-synthetic");
    assert_eq!(report["data"]["fixtures"].as_array().unwrap().len(), 1);
}
#[test]
fn fixture_command_preserves_unknown_field_and_reference_locations() {
    let (_directory, project, fixture) = setup();
    let original = fixture_value(&fixture);
    for pointer in ["/review/extra", "/expect/queue"] {
        let mut document = original.clone();
        if pointer == "/review/extra" {
            document["review"]["extra"] = json!("PRIVATE_FIXTURE_VALUE_CANARY");
        } else {
            document["expect"]["queue"] = json!(7);
        }
        std::fs::write(&fixture, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let exit = main_entry_from(
            [
                OsString::from("caseworkctl"),
                OsString::from("--format"),
                OsString::from("json"),
                OsString::from("test"),
                project.as_os_str().to_owned(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(exit, std::process::ExitCode::from(DOMAIN_REFUSAL_EXIT));
        assert!(err.is_empty());
        let report: Value = serde_json::from_slice(&out).unwrap();
        let diagnostic = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["path"] == pointer)
            .unwrap_or_else(|| panic!("missing fixture path {pointer}: {report}"));
        assert_eq!(diagnostic["source"]["file"], fixture.display().to_string());
        assert!(diagnostic["source"]["line"].as_u64().is_some());
        assert!(diagnostic["source"]["column"].as_u64().is_some());
        assert!(!String::from_utf8(out)
            .unwrap()
            .contains("PRIVATE_FIXTURE_VALUE_CANARY"));
    }
}
#[test]
fn fixture_check_collects_problems_from_every_file() {
    let (_directory, project, fixture) = setup();
    let mut document = fixture_value(&fixture);
    document["expect"] = json!({});
    std::fs::write(&fixture, serde_json::to_vec(&document).unwrap()).unwrap();
    let second = project.join("fixtures/second.yaml");
    document["expect"] = json!({"queue":"unknown"});
    std::fs::write(&second, serde_json::to_vec(&document).unwrap()).unwrap();
    let error = crate::project::test(&project, false).unwrap_err();
    let report = error.downcast_ref::<Report>().unwrap();
    for file in [&fixture, &second] {
        assert!(report.diagnostics().iter().any(|d| d
            .source
            .as_ref()
            .is_some_and(|s| s.file == file.display().to_string())));
    }
}
#[test]
fn empty_and_oversized_fixtures_keep_shared_file_diagnostics() {
    let (_directory, project, fixture) = setup();
    for bytes in [
        Vec::new(),
        vec![b'#'; registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES + 1],
    ] {
        std::fs::write(&fixture, bytes).unwrap();
        let error = crate::project::test(&project, false).unwrap_err();
        let report = error.downcast_ref::<Report>().unwrap();
        assert!(report.has_errors());
        assert!(report
            .diagnostics()
            .iter()
            .all(
                |d| (d.code.starts_with("config.") || d.code == "yaml.too-large")
                    && d.source
                        .as_ref()
                        .is_some_and(|s| s.file == fixture.display().to_string())
            ));
    }
}

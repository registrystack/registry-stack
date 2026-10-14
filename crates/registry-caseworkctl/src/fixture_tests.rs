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

fn run_json_check(project: &std::path::Path) -> (std::process::ExitCode, Value) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = main_entry_from(
        [
            OsString::from("caseworkctl"),
            OsString::from("--format"),
            OsString::from("json"),
            OsString::from("check"),
            project.as_os_str().to_owned(),
        ],
        &mut out,
        &mut err,
    );
    assert!(err.is_empty());
    (exit, serde_json::from_slice(&out).unwrap())
}

fn holiday_set(body: &str) -> String {
    format!(
        "apiVersion: id.registrystack.org/formats/casework/holiday-set/v1alpha1\nkind: CaseworkHolidaySet\nholidaySet: office-holidays\nrevision: 7\n{body}"
    )
}

#[test]
fn check_validates_project_holiday_sets_offline() {
    let (_directory, project, _fixture) = setup();
    let holidays = project.join("holiday-sets");
    std::fs::create_dir(&holidays).unwrap();
    std::fs::write(
        holidays.join("office.yaml"),
        holiday_set("dates: [2026-01-01]\n"),
    )
    .unwrap();

    let (exit, report) = run_json_check(&project);
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    assert_eq!(report["ok"], true);
    assert_eq!(report["data"]["networkAccess"], false);
    assert_eq!(report["data"]["databaseAccess"], false);
    assert!(report["data"]["filesChecked"].as_u64().unwrap() >= 2);
}

#[cfg(unix)]
#[test]
fn check_follows_a_reviewed_holiday_set_directory_alias() {
    let (_directory, project, _fixture) = setup();
    let holidays = project.join("calendar-inputs");
    std::fs::create_dir(&holidays).unwrap();
    let source = project.join("office-holidays.source");
    std::fs::write(&source, holiday_set("dates: [2026-01-01]\n")).unwrap();
    std::os::unix::fs::symlink(&source, holidays.join("office.yaml")).unwrap();
    std::os::unix::fs::symlink(&holidays, project.join("holiday-sets")).unwrap();

    let (exit, report) = run_json_check(&project);
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    assert_eq!(report["ok"], true);
    assert!(report["data"]["filesChecked"].as_u64().unwrap() >= 2);
}

#[test]
fn check_reports_a_holiday_set_path_that_is_not_a_directory() {
    let (_directory, project, _fixture) = setup();
    std::fs::write(project.join("holiday-sets"), "not a directory").unwrap();

    let (exit, report) = run_json_check(&project);
    assert_eq!(exit, std::process::ExitCode::from(DOMAIN_REFUSAL_EXIT));
    assert_eq!(
        report["diagnostics"][0]["code"],
        "casework.project.not-a-directory"
    );
    assert_eq!(
        report["diagnostics"][0]["source"]["file"],
        project.join("holiday-sets").display().to_string()
    );
}

#[test]
fn check_bounds_the_number_of_holiday_set_files_before_reading_them() {
    let (_directory, project, _fixture) = setup();
    let holidays = project.join("holiday-sets");
    std::fs::create_dir(&holidays).unwrap();
    for index in 0..=1024 {
        std::fs::write(holidays.join(format!("holiday-{index}.yaml")), "").unwrap();
    }

    let (exit, report) = run_json_check(&project);
    assert_eq!(exit, std::process::ExitCode::from(DOMAIN_REFUSAL_EXIT));
    assert_eq!(
        report["diagnostics"][0]["code"],
        "casework.project.too-many-files"
    );
    assert!(report["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("1024"));
}

#[cfg(unix)]
#[test]
fn check_reports_nested_special_and_broken_holiday_set_entries() {
    let (_directory, project, _fixture) = setup();
    let holidays = project.join("holiday-sets");
    std::fs::create_dir(&holidays).unwrap();
    std::fs::create_dir(holidays.join("nested")).unwrap();
    std::os::unix::fs::symlink("/dev/null", holidays.join("device.yaml")).unwrap();
    std::os::unix::fs::symlink("missing.yaml", holidays.join("broken.yaml")).unwrap();

    let (exit, report) = run_json_check(&project);
    assert_eq!(exit, std::process::ExitCode::from(DOMAIN_REFUSAL_EXIT));
    let codes = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        codes,
        std::collections::BTreeSet::from([
            "casework.project.not-a-regular-file",
            "casework.project.unread-directory",
            "casework.project.unreadable-file",
        ])
    );
    for diagnostic in report["diagnostics"].as_array().unwrap() {
        assert!(diagnostic["source"]["file"]
            .as_str()
            .unwrap()
            .starts_with(&project.display().to_string()));
    }
}

#[test]
fn check_reports_each_holiday_set_shape_error_at_its_authored_location() {
    let (_directory, project, _fixture) = setup();
    let holidays = project.join("holiday-sets");
    std::fs::create_dir(&holidays).unwrap();
    let path = holidays.join("office.yaml");
    for (body, pointer) in [
        ("dates: [2026-02-30]\n", "/dates/0"),
        ("dates: [2026-01-01, 2026-01-01]\n", "/dates/1"),
        ("dates: []\nunexpected: true\n", "/unexpected"),
    ] {
        std::fs::write(&path, holiday_set(body)).unwrap();
        let (exit, report) = run_json_check(&project);
        assert_eq!(exit, std::process::ExitCode::from(DOMAIN_REFUSAL_EXIT));
        let diagnostic = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|diagnostic| diagnostic["path"] == pointer)
            .unwrap_or_else(|| panic!("missing holiday-set path {pointer}: {report}"));
        assert_eq!(diagnostic["source"]["file"], path.display().to_string());
        assert!(diagnostic["source"]["line"].as_u64().is_some());
        assert!(diagnostic["source"]["column"].as_u64().is_some());
    }
}

#[test]
fn check_refuses_substitution_in_an_authored_holiday_set() {
    let (_directory, project, _fixture) = setup();
    let holidays = project.join("holiday-sets");
    std::fs::create_dir(&holidays).unwrap();
    let path = holidays.join("office.yaml");
    std::fs::write(
        &path,
        holiday_set("dates: [2026-01-01]\n").replace("office-holidays", "${CASEWORK_HOLIDAY_SET}"),
    )
    .unwrap();

    let (exit, report) = run_json_check(&project);
    assert_eq!(exit, std::process::ExitCode::from(DOMAIN_REFUSAL_EXIT));
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["path"] == "/holidaySet")
        .unwrap_or_else(|| panic!("missing holiday-set substitution diagnostic: {report}"));
    assert_eq!(diagnostic["code"], "config.substitution-not-allowed");
    assert_eq!(diagnostic["source"]["file"], path.display().to_string());
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

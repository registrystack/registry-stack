// SPDX-License-Identifier: Apache-2.0
//! `bregctl check --file`: one BReg tool file checked offline, by its kind.

use super::*;

const MARKER: &str = "CONFORMANCE-MARKER-Q7ZK2W";

fn repository(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two directories below the repository root")
        .join(relative)
}

fn check_file(file: &Path, arguments: &[&str]) -> Output {
    let mut command = vec!["check", "--file", path(file)];
    command.extend_from_slice(arguments);
    bregctl(&command)
}

fn json_report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn codes(report: &Value) -> Vec<&str> {
    report["diagnostics"]
        .as_array()
        .expect("the report lists diagnostics")
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().expect("a code"))
        .collect()
}

/// A scratch directory under the test's working directory, removed on drop.
fn scratch() -> TestProject {
    TestProject::from_registry_source(b"")
}

#[test]
fn every_registered_tool_example_checks_without_a_diagnostic() {
    let project = repository("products/breg/acceptance/asset-site-placement");
    for example in [
        "products/breg/examples/formats/schema-test-receipt.json",
        "products/breg/examples/formats/credentials.yaml",
        "products/breg/examples/formats/import.checkpoint.json",
        "products/breg/examples/formats/export.checkpoint.json",
        "products/breg/examples/formats/import.checkpoint.json.state",
        "products/breg/examples/formats/reviewed-migrations/modules/asset-site-placement-core/migrations/read-maintenance-note/descriptor.json",
        "products/breg/examples/formats/reviewed-migrations/modules/asset-site-placement-core/migrations/read-maintenance-note/rehearsal.json",
        "products/breg/examples/formats/retire-legacy-field-binding.json",
        "crates/registry-linkml/publicschema/starters/household.yaml",
        "products/breg/acceptance/facility/dev-clients.yaml",
        "products/breg/starters/seed-lots/core/examples/scenarios.json",
        "products/breg/examples/formats/dev-session/.breg/dev/state.json",
        "products/breg/examples/formats/dev-session/.breg/dev/source-prepared-source.json",
        "products/breg/examples/formats/dev-session/.breg/dev/source-transition.json",
    ] {
        let output = check_file(&repository(example), &["--format", "json", "--deny-warnings"]);
        let report = json_report(&output);
        assert_eq!(output.status.code(), Some(0), "{example}: {report}");
        assert_eq!(report["diagnostics"], json!([]), "{example}: {report}");
        assert_eq!(report["ok"], true, "{example}");
    }

    let journeys = repository("products/breg/acceptance/asset-site-placement/tests/journeys.yaml");
    let output = bregctl(&[
        "check",
        path(&project),
        "--file",
        path(&journeys),
        "--format",
        "json",
        "--deny-warnings",
    ]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["diagnostics"], json!([]), "{report}");
}

#[test]
fn a_warning_passes_unless_warnings_are_denied_in_both_output_forms() {
    let journeys = repository("products/breg/acceptance/asset-site-placement/tests/journeys.yaml");

    let output = check_file(&journeys, &["--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["ok"], true);
    assert_eq!(codes(&report), ["breg.check.project-not-read"]);
    assert_eq!(report["diagnostics"][0]["severity"], "warning");

    let output = check_file(&journeys, &[]);
    assert_eq!(output.status.code(), Some(0));
    let human = String::from_utf8_lossy(&output.stdout);
    assert!(human.starts_with("Check passed.\n"), "{human}");
    assert!(
        human.contains("warning[breg.check.project-not-read]"),
        "{human}"
    );
    assert!(human.contains("0 errors, 1 warning in 1 file"), "{human}");

    let output = check_file(&journeys, &["--deny-warnings"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let human = String::from_utf8_lossy(&output.stderr);
    assert!(
        human.starts_with("bregctl check refused the file: --deny-warnings refuses a warning.\n"),
        "{human}"
    );

    let output = check_file(&journeys, &["--format", "json", "--deny-warnings"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(report["ok"], false);
}

#[test]
fn a_refusal_is_positioned_and_named_in_both_output_forms() {
    let scratch = scratch();
    let credentials = scratch.path().join("credentials.yaml");
    let example = fs::read_to_string(repository(
        "products/breg/examples/formats/credentials.yaml",
    ))
    .unwrap();
    fs::write(
        &credentials,
        example.replacen("stepId: planner-gets-asset", "stepId: create-asset", 1),
    )
    .unwrap();

    let output = check_file(&credentials, &["--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(codes(&report), ["breg.credentials.duplicate-binding"]);
    assert_eq!(report["diagnostics"][0]["path"], "/bindings/1");
    assert_eq!(report["diagnostics"][0]["source"]["line"], 12);

    let output = check_file(&credentials, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let human = String::from_utf8_lossy(&output.stderr);
    assert!(
        human.starts_with("bregctl check refused the file.\n"),
        "{human}"
    );
    assert!(
        human.contains("error[breg.credentials.duplicate-binding]"),
        "{human}"
    );

    // A file of another product's kind is refused by the shared reader.
    let output = check_file(
        &repository("products/breg/acceptance/asset-site-placement/registry.yaml"),
        &["--format", "json"],
    );
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(codes(&report), ["config.wrong-kind"]);
}

#[test]
fn usage_errors_exit_two_and_an_unreadable_file_exits_three() {
    let journeys = repository("products/breg/acceptance/asset-site-placement/tests/journeys.yaml");
    for arguments in [
        vec![
            "check",
            "--file",
            path(&journeys),
            "--package",
            "build/package",
        ],
        vec!["check", "--file", path(&journeys), "--production"],
    ] {
        let output = bregctl(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty());
    }

    let scratch = scratch();
    let output = check_file(&scratch.path().join("absent.yaml"), &["--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert_eq!(codes(&report), ["breg.check.file-unreadable"]);

    // The bounded reader refuses a parent-directory component, so the
    // refusal names that fix too.
    let output = check_file(
        &repository("crates/../products/breg/examples/formats/credentials.yaml"),
        &["--format", "json"],
    );
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert!(
        report["diagnostics"][0]["suggestedAction"]
            .as_str()
            .is_some_and(|action| action.contains("no `..`")),
        "{report}"
    );
}

/// CFG-CHECK-1: the check confirms a reference names a declared provider
/// and never opens the secret. CFG-SEC-3: no output repeats a value.
#[test]
fn a_clients_check_reads_no_secret_and_repeats_no_value() {
    let scratch = scratch();
    let example = fs::read_to_string(repository(
        "products/breg/acceptance/facility/dev-clients.yaml",
    ))
    .unwrap();
    let clients = format!(
        "{example}secretProviders:
  file:
    root: {}
reviewAuthorities:
  casework-a:
    endpoint: http://127.0.0.1:18096/
    profile: integration-requester
    producerId: registry-producer
    recoveryDays: 7
    client: facility-operator
    completionTokenRef: secret:file/completion-token
    completionRecipient: registry-breg
",
        scratch.path().join("no-secrets-here").display()
    );
    let file = scratch.path().join("dev-clients.yaml");
    fs::write(&file, &clients).unwrap();
    let output = check_file(&file, &["--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["diagnostics"], json!([]));
    assert!(!scratch.path().join("no-secrets-here").exists());

    for (planted, code) in [
        (
            clients.replace(
                "secret:file/completion-token",
                &format!("secret:vault/{MARKER}"),
            ),
            "config.invalid-value",
        ),
        (
            clients.replace(
                "secret:file/completion-token",
                &format!("secret:env/{}", MARKER.replace('-', "_")),
            ),
            "breg.dev-clients.refused",
        ),
        (
            clients.replace(
                "endpoint: http://127.0.0.1:18096/",
                &format!("endpoint: http://{MARKER}.invalid/"),
            ),
            "breg.dev-clients.refused",
        ),
    ] {
        fs::write(&file, &planted).unwrap();
        for arguments in [&["--format", "json"][..], &[][..]] {
            let output = check_file(&file, arguments);
            assert_eq!(output.status.code(), Some(1), "{planted}");
            let rendered = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(rendered.contains(code), "{rendered}");
            assert!(!rendered.contains(MARKER), "{rendered}");
            assert!(!rendered.contains("Q7ZK2W"), "{rendered}");
        }
    }
}

/// CFG-YAML-6: a file over the shared bound is refused by the shared reader,
/// however far over it is.
#[test]
fn an_oversize_file_is_refused_by_the_shared_reader() {
    let scratch = scratch();
    let file = scratch.path().join("credentials.yaml");
    for size in [1_048_577, 3 * 1_048_576] {
        fs::write(&file, "#\n".repeat(size / 2 + 1)).unwrap();
        let output = check_file(&file, &["--format", "json"]);
        let report = json_report(&output);
        assert_eq!(output.status.code(), Some(1), "{size}: {report}");
        assert_eq!(codes(&report), ["yaml.too-large"], "{size}");
    }
}

/// CFG-SEC-2: a file BReg reads as written refuses a substitution
/// expression; a file a command wrote keeps the text it copied.
#[test]
fn an_expression_is_refused_in_a_file_read_as_written_and_kept_in_a_written_one() {
    let scratch = scratch();
    let credentials = scratch.path().join("credentials.yaml");
    let example = fs::read_to_string(repository(
        "products/breg/examples/formats/credentials.yaml",
    ))
    .unwrap();
    fs::write(
        &credentials,
        example.replacen(
            "journeyId: asset-and-site-caller-surfaces",
            "journeyId: \"${JOURNEY}\"",
            1,
        ),
    )
    .unwrap();
    let output = check_file(&credentials, &["--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(codes(&report), ["config.substitution-not-allowed"]);
    assert_eq!(report["diagnostics"][0]["path"], "/bindings/0/journeyId");
    assert!(report["diagnostics"][0]["suggestedAction"]
        .as_str()
        .is_some_and(|action| action.contains("secret reference")));

    let transition = scratch.path().join("source-transition.json");
    let example = fs::read_to_string(repository(
        "products/breg/examples/formats/dev-session/.breg/dev/source-transition.json",
    ))
    .unwrap();
    let copied = "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\\n";
    assert!(example.contains(copied));
    fs::write(
        &transition,
        example.replace(copied, "url: ${BREG_DATABASE_URL}\\n"),
    )
    .unwrap();
    let output = check_file(&transition, &["--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["diagnostics"], json!([]));
}

/// A project `bregctl init` wrote, in a scratch directory removed on drop.
fn initialized() -> (TestProject, PathBuf) {
    let scratch = scratch();
    let project = scratch.path().join("project");
    let output = bregctl(&["init", path(&project)]);
    assert!(output.status.success(), "{output:?}");
    (scratch, project)
}

/// The diagnostics a report holds about `file`.
fn diagnostics_about(report: &Value, file: &Path) -> Vec<Value> {
    report["diagnostics"]
        .as_array()
        .expect("the report lists diagnostics")
        .iter()
        .filter(|diagnostic| diagnostic["source"]["file"] == path(file))
        .cloned()
        .collect()
}

/// CFG-CHECK-2: the project check reads the journeys and the development
/// clients the project holds, and reports about each what `check --file`
/// reports about it.
#[test]
fn a_project_check_reads_the_journeys_and_the_development_clients_it_holds() {
    let (_scratch, project) = initialized();
    let output = bregctl(&["check", path(&project)]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let human = String::from_utf8_lossy(&output.stdout);
    assert!(human.contains("0 errors, 2 warnings in 4 files"), "{human}");

    for (relative, with_project) in [("tests/journeys.yaml", true), ("dev-clients.yaml", false)] {
        let file = project.join(relative);
        let written = fs::read_to_string(&file).unwrap();
        fs::write(&file, format!("{written}unexpected: true\n")).unwrap();

        let alone = if with_project {
            bregctl(&[
                "check",
                path(&project),
                "--file",
                path(&file),
                "--format",
                "json",
            ])
        } else {
            check_file(&file, &["--format", "json"])
        };
        let expected = diagnostics_about(&json_report(&alone), &file);
        assert_eq!(expected.len(), 1, "{relative}: {expected:?}");
        assert_eq!(expected[0]["code"], "config.unknown-key", "{relative}");

        let output = bregctl(&["check", path(&project), "--format", "json"]);
        let report = json_report(&output);
        assert_eq!(output.status.code(), Some(1), "{relative}: {report}");
        assert_eq!(report["ok"], false, "{relative}");
        assert_eq!(
            diagnostics_about(&report, &file),
            expected,
            "{relative}: {report}"
        );

        fs::write(&file, written).unwrap();
    }
}

/// CFG-ID-4: a journey that names an access profile the project does not
/// declare is refused by the project check, as `check PROJECT --file` refuses
/// it.
#[test]
fn a_project_check_resolves_the_journeys_against_the_project() {
    let (_scratch, project) = initialized();
    let file = project.join("tests/journeys.yaml");
    let written = fs::read_to_string(&file).unwrap();
    let edited = written.replacen(
        "accessProfile: operator",
        "accessProfile: absent-profile",
        1,
    );
    assert_ne!(edited, written);
    fs::write(&file, edited).unwrap();

    let alone = bregctl(&[
        "check",
        path(&project),
        "--file",
        path(&file),
        "--format",
        "json",
    ]);
    let expected = diagnostics_about(&json_report(&alone), &file);
    assert_eq!(expected.len(), 1, "{expected:?}");
    assert!(
        expected[0]["code"]
            .as_str()
            .is_some_and(|code| code.starts_with("breg.journeys.")),
        "{expected:?}"
    );

    let output = bregctl(&["check", path(&project), "--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(diagnostics_about(&report, &file), expected, "{report}");
}

/// CFG-CHECK-2: every `.yaml` and `.yml` file under `tests/` is read and
/// identified by its envelope. A second journeys document is checked, a file
/// whose kind is not a BReg tool file's is refused instead of skipped, and a
/// file that is not YAML is left alone.
#[test]
fn a_project_check_reads_every_yaml_file_under_tests() {
    let (_scratch, project) = initialized();
    let journeys = fs::read_to_string(project.join("tests/journeys.yaml")).unwrap();
    fs::write(project.join("tests/README.md"), "Notes.\n").unwrap();
    fs::write(project.join("tests/more-journeys.yml"), &journeys).unwrap();
    let output = bregctl(&["check", path(&project)]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let human = String::from_utf8_lossy(&output.stdout);
    assert!(human.contains("0 errors, 2 warnings in 5 files"), "{human}");

    let second = project.join("tests/more-journeys.yml");
    fs::write(&second, format!("{journeys}unexpected: true\n")).unwrap();
    let other = project.join("tests/other.yaml");
    fs::write(
        &other,
        "apiVersion: example.invalid/formats/other/v1\nkind: OtherDocument\n",
    )
    .unwrap();

    let output = bregctl(&["check", path(&project), "--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    for file in [&second, &other] {
        let expected = diagnostics_about(
            &json_report(&bregctl(&[
                "check",
                path(&project),
                "--file",
                path(file),
                "--format",
                "json",
            ])),
            file,
        );
        assert!(!expected.is_empty(), "{}", file.display());
        assert_eq!(diagnostics_about(&report, file), expected, "{report}");
    }
}

/// CFG-DIAG-5: a refused `registry.yaml` does not hide what is wrong with
/// the journeys beside it.
#[test]
fn a_project_check_reads_the_journeys_of_a_project_it_refuses() {
    let (_scratch, project) = initialized();
    for relative in ["registry.yaml", "tests/journeys.yaml"] {
        let file = project.join(relative);
        let written = fs::read_to_string(&file).unwrap();
        fs::write(&file, format!("{written}unexpected: true\n")).unwrap();
    }
    let output = bregctl(&["check", path(&project), "--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    for relative in ["registry.yaml", "tests/journeys.yaml"] {
        let found = diagnostics_about(&report, &project.join(relative));
        assert_eq!(found.len(), 1, "{relative}: {report}");
        assert_eq!(found[0]["code"], "config.unknown-key", "{relative}");
    }
}

/// CFG-CHECK-2: the check never skips a YAML file silently. It reads the
/// files directly under `tests/`, so a directory there is named with a
/// warning, and a `tests` that cannot be listed is an error.
#[test]
fn a_project_check_names_what_it_does_not_read_under_tests() {
    let (_scratch, project) = initialized();
    let nested = project.join("tests/more");
    fs::create_dir(&nested).unwrap();
    fs::copy(project.join("tests/journeys.yaml"), nested.join("j.yaml")).unwrap();

    let output = bregctl(&["check", path(&project), "--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    let found = diagnostics_about(&report, &nested);
    assert_eq!(found.len(), 1, "{report}");
    assert_eq!(found[0]["code"], "breg.check.unread-directory");
    assert_eq!(found[0]["severity"], "warning");
    let denied = bregctl(&["check", path(&project), "--deny-warnings"]);
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");

    fs::remove_dir_all(project.join("tests")).unwrap();
    fs::write(project.join("tests"), "not a directory\n").unwrap();
    let output = bregctl(&["check", path(&project), "--format", "json"]);
    let report = json_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    let found = diagnostics_about(&report, &project.join("tests"));
    assert_eq!(found.len(), 1, "{report}");
    assert_eq!(found[0]["code"], "breg.check.directory-unreadable");
    assert_eq!(found[0]["severity"], "error");
}

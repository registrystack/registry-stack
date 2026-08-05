use std::collections::BTreeSet;
use std::fs;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args(args)
        .env_remove("REGISTRYCTL_ENVIRONMENT")
        .output()
        .expect("registryctl runs")
}

fn stdout(args: &[&str]) -> String {
    let output = run(args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "registryctl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("help is UTF-8")
}

fn command_names(help: &str) -> BTreeSet<String> {
    let mut in_commands = false;
    let mut names = BTreeSet::new();
    for line in help.lines() {
        if line == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands && line.ends_with(':') && !line.starts_with(' ') {
            break;
        }
        if in_commands {
            let trimmed = line.trim_start();
            if line.starts_with("  ") && !line.starts_with("   ") && !trimmed.is_empty() {
                if let Some(name) = trimmed.split_whitespace().next() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

#[test]
fn root_help_exposes_only_the_ten_1_0_roots_in_newcomer_order() {
    let help = stdout(&["--help"]);
    let expected = BTreeSet::from([
        "build".to_string(),
        "check".to_string(),
        "deploy".to_string(),
        "dev".to_string(),
        "doctor".to_string(),
        "init".to_string(),
        "review".to_string(),
        "test".to_string(),
        "tooling".to_string(),
        "trust".to_string(),
    ]);
    assert_eq!(command_names(&help), expected, "{help}");

    let positions = ["init", "test", "dev", "check", "build", "deploy", "doctor"].map(|name| {
        help.find(&format!("  {name}"))
            .unwrap_or_else(|| panic!("missing {name} in {help}"))
    });
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "ordinary workflow is not newcomer-first: {help}"
    );
    assert!(help.contains("Newcomer workflow:"));
    assert!(help.contains("Start here: registryctl init my-registry --template spreadsheet"));
    assert!(help.find("  doctor").unwrap() < help.find("  review").unwrap());
}

#[test]
fn advanced_help_exposes_the_closed_nesting() {
    assert_eq!(
        command_names(&stdout(&["review", "--help"])),
        BTreeSet::from(["compare".to_string()])
    );
    assert_eq!(
        command_names(&stdout(&["trust", "--help"])),
        BTreeSet::from([
            "anchor".to_string(),
            "approved-set".to_string(),
            "bundle".to_string(),
        ])
    );
    assert_eq!(
        command_names(&stdout(&["trust", "anchor", "--help"])),
        BTreeSet::from(["create".to_string(), "rotate".to_string()])
    );
    assert_eq!(
        command_names(&stdout(&["trust", "bundle", "--help"])),
        BTreeSet::from([
            "inspect".to_string(),
            "sign".to_string(),
            "verify".to_string(),
        ])
    );
    assert_eq!(
        command_names(&stdout(&["trust", "approved-set", "--help"])),
        BTreeSet::from(["assemble".to_string()])
    );
    assert_eq!(
        command_names(&stdout(&["tooling", "--help"])),
        BTreeSet::from([
            "diagnostics".to_string(),
            "editor".to_string(),
            "language-server".to_string(),
            "reference".to_string(),
            "schema".to_string(),
        ])
    );
    assert_eq!(
        command_names(&stdout(&["deploy", "--help"])),
        BTreeSet::from(["generate".to_string(), "verify".to_string()])
    );
    assert_eq!(
        command_names(&stdout(&["dev", "--help"])),
        BTreeSet::from([
            "down".to_string(),
            "logs".to_string(),
            "smoke".to_string(),
            "status".to_string(),
        ])
    );
}

#[test]
fn removed_pre_1_0_roots_and_aliases_are_usage_errors() {
    for root in [
        "update-check",
        "__update-check-refresh",
        "add",
        "start",
        "stop",
        "restart",
        "status",
        "open",
        "smoke",
        "logs",
        "preflight",
        "capabilities",
        "compare",
        "promote",
        "migrate",
        "bundle",
        "anchor",
        "authoring",
        "project",
        "bruno",
        "__registryctl-cel-worker-v1",
    ] {
        let output = run(&[root]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "removed root {root} was accepted: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert_eq!(run(&["init", "relay"]).status.code(), Some(2));
    assert_eq!(run(&["test", "--live"]).status.code(), Some(2));
}

#[test]
fn stable_flags_have_strict_values_and_documented_meanings() {
    let root_help = stdout(&["--help"]);
    assert!(root_help.contains("-C, --project-dir <DIRECTORY>"));

    let init_help = stdout(&["init", "--help"]);
    assert!(init_help.contains("<PROJECT_DIRECTORY>"));
    assert!(
        init_help.contains("Absent or empty real directory"),
        "{init_help}"
    );
    assert!(init_help.contains("--template <TEMPLATE>"));
    assert!(
        init_help.contains("possible values: spreadsheet, http"),
        "{init_help}"
    );
    for internal_fixture in ["dhis2-tracker", "opencrvs-dci", "fhir-r4", "snapshot"] {
        assert!(!init_help.contains(internal_fixture), "{init_help}");
        assert_eq!(
            run(&["init", "project", "--template", internal_fixture])
                .status
                .code(),
            Some(2)
        );
    }
    assert!(!init_help.contains("--from"));

    let review_help = stdout(&["review", "compare", "--help"]);
    assert!(review_help.contains("--against <AGAINST>"));
    assert!(review_help.contains("--fail-on-change"));

    let deploy_help = stdout(&["deploy", "generate", "--help"]);
    assert!(deploy_help.contains("--approved-set <APPROVED_SET>"));
    assert!(deploy_help.contains("--output-dir <OUTPUT_DIR>"));
    assert!(deploy_help.contains("--binding <BINDING>"));
    let deploy_verify_help = stdout(&["deploy", "verify", "--help"]);
    assert!(deploy_verify_help.contains("--expected-closure-sha256 <EXPECTED_CLOSURE_SHA256>"));
    assert!(deploy_verify_help.contains("--check-operator-files"));
    assert!(!deploy_verify_help.contains("--parent-compose"));

    let anchor_help = stdout(&["trust", "anchor", "create", "--help"]);
    assert!(anchor_help.contains("--public-key <JWK_FILE>"));
    assert!(anchor_help.contains("Public Ed25519 JSON Web Key (JWK) file"));
    assert!(anchor_help.contains("--output-file <FILE>"));

    let bundle_help = stdout(&["trust", "bundle", "verify", "--help"]);
    assert!(bundle_help.contains("--bundle-dir <SIGNED_ARTIFACT_DIRECTORY>"));
    assert!(bundle_help.contains("Signed artifact directory produced by"));

    assert_eq!(run(&["check", "--format", "yaml"]).status.code(), Some(2));
    assert_eq!(run(&["check", "--format", "jsonl"]).status.code(), Some(2));
}

#[test]
fn trust_lane_selectors_are_relay_only() {
    let anchor_help = stdout(&["trust", "anchor", "create", "--help"]);
    assert!(
        anchor_help.contains("possible values: relay-public, relay-consultation"),
        "{anchor_help}"
    );
    assert!(!anchor_help.contains("notary"), "{anchor_help}");

    let approved_set_help = stdout(&["trust", "approved-set", "assemble", "--help"]);
    assert!(
        approved_set_help.contains("--relay-public"),
        "{approved_set_help}"
    );
    assert!(
        approved_set_help.contains("--relay-consultation"),
        "{approved_set_help}"
    );
    assert!(!approved_set_help.contains("notary"), "{approved_set_help}");

    assert_eq!(
        run(&[
            "trust",
            "anchor",
            "create",
            "--lane",
            "notary",
            "--input",
            "unused",
            "--public-key",
            "unused",
            "--threshold",
            "1",
            "--output-file",
            "unused",
        ])
        .status
        .code(),
        Some(2)
    );
}

#[test]
fn check_explain_adds_the_classifier_safe_review_to_human_output() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    let project_argument = project.to_str().expect("temporary path is UTF-8");
    let initialized = run(&["init", project_argument, "--template", "http"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let ordinary = run(&["-C", project_argument, "check"]);
    assert!(
        ordinary.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    let ordinary_stdout = String::from_utf8(ordinary.stdout).expect("check output is UTF-8");
    assert!(!ordinary_stdout.contains("Explanation:"));

    let explained = run(&["-C", project_argument, "check", "--explain"]);
    assert!(
        explained.status.success(),
        "{}",
        String::from_utf8_lossy(&explained.stderr)
    );
    let explained_stdout = String::from_utf8(explained.stdout).expect("check output is UTF-8");
    for expected in [
        "Explanation: registry.project.explanation.v1 for fictional-citizen-registry in local",
        "integration person-record",
        "[authored, effective]",
        "environment local /relay/consultation/client_id = <redacted:sensitive>",
        "<redacted:redacted_fixture>",
        "Full provenance and constraint metadata: rerun with --format json.",
    ] {
        assert!(
            explained_stdout.contains(expected),
            "{expected:?} is missing from {explained_stdout}"
        );
    }
    assert!(
        explained_stdout.contains(&format!(
            "Next: registryctl -C '{}' build",
            project.display()
        )),
        "{explained_stdout}"
    );
    assert!(!explained_stdout.contains("\"reported_value\""));
}

#[test]
fn project_next_actions_preserve_explicit_project_and_environment_selection() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    let project_argument = project.to_str().expect("temporary path is UTF-8");
    let initialized = run(&["init", project_argument, "--template", "http"]);
    assert!(initialized.status.success());

    for (command, next) in [
        (
            "test",
            format!(
                "Next: registryctl -C '{}' dev --environment 'local'",
                project.display()
            ),
        ),
        (
            "check",
            format!(
                "Next: registryctl -C '{}' build --environment 'local'",
                project.display()
            ),
        ),
    ] {
        let output = run(&["-C", project_argument, command, "--environment", "local"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("command output is UTF-8");
        assert!(stdout.contains(&next), "{next:?} is missing from {stdout}");
    }
}

#[test]
fn spreadsheet_build_does_not_send_a_file_backed_project_to_governed_approval() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("spreadsheet-project");
    let project_argument = project.to_str().expect("temporary path is UTF-8");
    let initialized = run(&["init", project_argument, "--template", "spreadsheet"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let build = run(&["-C", project_argument, "build"]);
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let output = String::from_utf8(build.stdout).expect("build output is UTF-8");
    assert!(
        output.contains(
            "Next: bind an operator-managed source in a separate governed environment and rerun registryctl test; do not sign this file-backed build"
        ),
        "{output}"
    );
    assert!(
        !output.contains("Next: registryctl trust anchor create"),
        "{output}"
    );

    let json_build = run(&["-C", project_argument, "build", "--format", "json"]);
    assert!(
        json_build.status.success(),
        "{}",
        String::from_utf8_lossy(&json_build.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&json_build.stdout).expect("build report is JSON");
    assert_eq!(
        report["output_owner"], "country implementer and reviewer",
        "a development-only file build must remain with its implementer and reviewer"
    );
}

#[test]
fn governed_handoff_help_names_ownership_mutation_and_the_exact_next_command() {
    for (args, next) in [
        (
            &["build", "--help"][..],
            "registryctl trust anchor create --help",
        ),
        (&["review", "compare", "--help"][..], "registryctl build"),
        (
            &["trust", "anchor", "create", "--help"][..],
            "registryctl trust bundle sign --help",
        ),
        (
            &["trust", "anchor", "rotate", "--help"][..],
            "registryctl trust bundle sign --help",
        ),
        (
            &["trust", "bundle", "inspect", "--help"][..],
            "registryctl trust bundle verify --bundle-dir <signed-artifact-directory> --anchor <file>",
        ),
        (
            &["trust", "bundle", "verify", "--help"][..],
            "registryctl trust approved-set assemble --help",
        ),
        (
            &["trust", "bundle", "sign", "--help"][..],
            "registryctl trust bundle verify --bundle-dir <signed-artifact-directory> --anchor <signed-artifact-directory>/anchor.json",
        ),
        (
            &["trust", "approved-set", "assemble", "--help"][..],
            "registryctl deploy generate --approved-set <file> --output-dir <directory>",
        ),
        (
            &["deploy", "generate", "--help"][..],
            "registryctl deploy verify --package <directory>",
        ),
        (
            &["deploy", "verify", "--help"][..],
            "docker compose --env-file generated/compose.empty.env",
        ),
    ] {
        let help = stdout(args);
        for label in [
            "Input owner:",
            "Output owner:",
            "Mutation:",
            "Next command:",
        ] {
            assert!(
                help.contains(label),
                "{args:?} help is missing {label:?}: {help}"
            );
        }
        assert!(
            help.contains(next),
            "{args:?} help is missing exact next command {next:?}: {help}"
        );
    }
}

#[test]
fn build_help_exposes_explicit_anchor_rotation_selection() {
    let help = stdout(&["build", "--help"]);
    assert!(help.contains("--rotate-anchor <LANE>"), "{help}");
    assert!(
        help.contains("authenticated trust-anchor rotation"),
        "{help}"
    );
}

#[test]
fn project_dir_is_global_before_or_after_the_command() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::write(
        temporary.path().join("registry-stack.yaml"),
        "registry: [invalid\n",
    )
    .expect("invalid project fixture writes");
    fs::create_dir(temporary.path().join("environments")).expect("environment directory writes");
    fs::write(
        temporary.path().join("environments/local.yaml"),
        "version: 1\n",
    )
    .expect("environment fixture writes");
    let directory = temporary.path().to_str().expect("temporary path is UTF-8");

    for args in [
        vec!["-C", directory, "check"],
        vec!["check", "-C", directory],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "global -C was not accepted for {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn trace_and_watch_are_composable_human_test_options() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::write(
        temporary.path().join("registry-stack.yaml"),
        "registry: [invalid\n",
    )
    .expect("invalid project fixture writes");
    fs::create_dir(temporary.path().join("environments")).expect("environment directory writes");
    fs::write(
        temporary.path().join("environments/local.yaml"),
        "version: 1\n",
    )
    .expect("environment fixture writes");

    let output = run(&[
        "-C",
        temporary.path().to_str().expect("temporary path is UTF-8"),
        "test",
        "--trace",
        "--watch",
    ]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "trace and watch should reach project validation together: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn trace_renders_the_selected_synthetic_fixture_in_human_output() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    let project_argument = project.to_str().expect("temporary path is UTF-8");
    let initialized = run(&["init", project_argument, "--template", "http"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let ordinary = run(&[
        "-C",
        project_argument,
        "test",
        "--integration",
        "person-record",
        "--fixture",
        "active-person",
    ]);
    assert!(
        ordinary.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    let ordinary_stdout =
        String::from_utf8(ordinary.stdout).expect("ordinary test output is UTF-8");
    assert!(!ordinary_stdout.contains("PASS person-record.active-person"));

    let traced = run(&[
        "-C",
        project_argument,
        "test",
        "--integration",
        "person-record",
        "--fixture",
        "active-person",
        "--trace",
    ]);
    assert!(
        traced.status.success(),
        "{}",
        String::from_utf8_lossy(&traced.stderr)
    );
    let traced_stdout = String::from_utf8(traced.stdout).expect("trace test output is UTF-8");
    for expected in [
        "PASS person-record.active-person",
        "inputs: person_id",
        "calls:",
        "outputs: active",
        "outcome: match",
    ] {
        assert!(
            traced_stdout.contains(expected),
            "{expected:?} is missing from {traced_stdout}"
        );
    }
    assert!(
        traced_stdout.contains(&format!("Next: registryctl -C '{}' dev", project.display())),
        "{traced_stdout}"
    );
}

#[test]
fn shipped_http_starter_readme_uses_the_1_0_hierarchy_and_runtime_ownership() {
    let readme = include_str!("../assets/project-starters/bounded-http/README.md");

    for obsolete in [
        "registryctl authoring",
        "registryctl preflight",
        "--project-dir .",
    ] {
        assert!(
            !readme.contains(obsolete),
            "{obsolete:?} remains in {readme}"
        );
    }
    for current in [
        "registryctl -C . tooling editor",
        "registryctl -C . test",
        "registryctl -C . check --environment local --explain",
        "registryctl -C . build --environment local",
        "registryctl -C . dev --environment local --detach",
        "registryctl -C . dev --environment local smoke",
        "registryctl -C . dev --environment local down",
        ".registry-stack/dev-artifacts/",
        ".registry-stack/dev/",
        "not production",
        "https://docs.registrystack.org/operate/approve-initial-baseline/",
        "https://docs.registrystack.org/operate/single-node-compose-behind-proxy/",
        "explicit and separate from `registryctl dev`",
    ] {
        assert!(
            readme.contains(current),
            "{current:?} is missing from {readme}"
        );
    }
    assert!(
        readme.find("registryctl -C . test").unwrap()
            < readme
                .find("registryctl -C . dev --environment local --detach")
                .unwrap(),
        "starter begins dev before offline validation: {readme}"
    );
}

#[test]
fn bare_deploy_prints_help_without_performing_an_action() {
    let output = run(&["deploy"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).expect("deploy help is UTF-8");
    assert!(text.contains("Generate or verify a governed deployment package"));
    assert!(text.contains("Usage: registryctl deploy [OPTIONS] [COMMAND]"));
    assert!(text.contains("generate"));
    assert!(text.contains("verify"));
    assert!(!text.contains("help  Print this message"));
}

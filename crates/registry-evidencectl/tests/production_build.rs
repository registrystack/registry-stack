#![cfg(unix)]

//! Production-build filesystem and delegation invariants.
//!
//! These tests deliberately replace the sibling `evidence` binary with a
//! value-free recorder. They pin the adopter tool's responsibilities without
//! copying bundle or fixture semantics out of the runtime.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LOCAL_URI: &str = "urn:registrystack:evidence:local:forbidden";
const SECRET_CANARY: &str = "production-build-secret-canary";

#[test]
fn build_is_create_only_and_never_changes_an_existing_output() {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.output).expect("existing output");
    fs::write(fixture.output.join("owned.txt"), "preserve me\n").expect("existing file");

    let output = fixture.build();

    assert_failed(&output, "existing output must be refused");
    assert_eq!(
        fs::read_to_string(fixture.output.join("owned.txt")).unwrap(),
        "preserve me\n"
    );
    assert!(fixture.invocations().is_empty());
    fixture.assert_no_staging_residue();
}

#[test]
fn build_rejects_output_inside_the_editable_project_without_modifying_it() {
    let fixture = Fixture::new();
    let candidate = fixture.project.join("candidate");
    let before = snapshot(&fixture.project);

    let output = fixture.build_with(&fixture.project, &fixture.target, &candidate);

    assert_failed(&output, "project-contained output must be refused");
    assert!(!candidate.exists());
    assert_eq!(snapshot(&fixture.project), before);
    assert!(fixture.invocations().is_empty());
    fixture.assert_no_staging_residue();
}

#[test]
fn build_rejects_symlinked_project_target_output_parent_and_artifact() {
    for boundary in ["project", "target", "output-parent", "artifact"] {
        let fixture = Fixture::new();
        let mut project = fixture.project.clone();
        let mut target = fixture.target.clone();
        let mut output = fixture.output.clone();
        match boundary {
            "project" => {
                project = fixture.root.join("project-link");
                symlink(&fixture.project, &project).expect("project symlink");
            }
            "target" => {
                target = fixture.root.join("target-link");
                symlink(&fixture.target, &target).expect("target symlink");
            }
            "output-parent" => {
                let actual = fixture.root.join("actual-output-parent");
                fs::create_dir(&actual).expect("actual output parent");
                let linked = fixture.root.join("linked-output-parent");
                symlink(&actual, &linked).expect("output parent symlink");
                output = linked.join("candidate");
            }
            "artifact" => {
                let derivation = fixture.project.join("derivations/answer.rhai");
                fs::remove_file(&derivation).expect("remove regular derivation");
                let outside = fixture.root.join("outside.rhai");
                fs::write(
                    &outside,
                    "fn answer(facts, selectors, context) { #{allowed: true} }\n",
                )
                .expect("outside derivation");
                symlink(outside, derivation).expect("artifact symlink");
            }
            _ => unreachable!(),
        }

        let result = fixture.build_with(&project, &target, &output);
        assert_failed(&result, boundary);
        assert!(!output.exists(), "{boundary} published an output");
        assert!(
            fixture.invocations().is_empty(),
            "{boundary} reached Evidence"
        );
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn failed_runtime_check_leaves_no_output_or_private_staging() {
    let fixture = Fixture::new();

    let output = fixture.build_failing("check");

    assert_failed(&output, "runtime rejection must fail the build");
    assert!(!fixture.output.exists());
    fixture.assert_no_staging_residue();
    assert_eq!(fixture.steps(), ["check"]);
    assert_value_free(&output);
}

#[test]
fn a_rejected_bundle_and_fixture_name_the_command_that_shows_the_diagnosis() {
    let rejected_bundle = Fixture::new();
    let project = fs::canonicalize(&rejected_bundle.project).expect("canonical project");

    let output = rejected_bundle.build_failing("check");

    assert_failed(&output, "a rejected bundle must fail the build");
    let message = stderr(&output);
    assert!(
        message.contains(&format!(
            "Run `evidencectl fixtures run --project {}` to read the diagnosis Evidence prints.",
            project.display()
        )),
        "the refusal names the command that shows the diagnosis: {message}"
    );
    assert_value_free(&output);

    let rejected_fixture = Fixture::new();
    let project = fs::canonicalize(&rejected_fixture.project).expect("canonical project");

    let output = rejected_fixture.build_failing("fixture:fixtures/answer.yaml");

    assert_failed(&output, "a rejected fixture must fail the build");
    let message = stderr(&output);
    assert!(
        message.contains(&format!(
            "Run `evidencectl fixtures run --project {} --fixture fixtures/answer.yaml` to read the diagnosis Evidence prints.",
            project.display()
        )),
        "the refusal names the rejected fixture with the command: {message}"
    );
    assert_value_free(&output);
}

#[test]
fn a_mismatched_evidence_binary_is_refused_before_any_step() {
    let fixture = Fixture::new();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_VERSION", "0.0.0-other")
        .output()
        .expect("evidencectl build starts");

    assert_failed(&output, "a mismatched evidence binary must fail the build");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0.0.0-other"),
        "the refusal names the reported version: {stderr}"
    );
    assert!(
        stderr.contains(registry_platform_buildinfo::DISPLAY_VERSION),
        "the refusal names this build: {stderr}"
    );
    assert!(!fixture.output.exists());
    assert!(
        fixture.invocations().is_empty(),
        "a mismatched binary was handed work"
    );
    fixture.assert_no_staging_residue();
}

#[test]
fn an_evidence_binary_that_does_not_identify_itself_is_refused_before_any_step() {
    let fixture = Fixture::new();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_VERSION", "")
        .output()
        .expect("evidencectl build starts");

    assert_failed(
        &output,
        "an unidentified evidence binary must fail the build",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did not report an Evidence runtime version"),
        "the refusal names what was missing: {stderr}"
    );
    assert!(!fixture.output.exists());
    assert!(
        fixture.invocations().is_empty(),
        "an unidentified binary was handed work"
    );
    fixture.assert_no_staging_residue();
}

#[test]
fn successful_build_copies_runtime_exactly_and_excludes_local_and_validation_secrets() {
    let fixture = Fixture::new();
    let local = fixture.project.join(".evidence/dev");
    fs::create_dir_all(&local).expect("local state");
    fs::write(local.join("disposable-private-key"), SECRET_CANARY).expect("local secret");
    let runtime = fs::read(&fixture.runtime).expect("target runtime");

    let output = fixture.build();

    assert_success(&output, "production build");
    assert_eq!(
        fs::read(fixture.output.join("runtime.yaml")).unwrap(),
        runtime
    );
    let snapshot = snapshot(&fixture.output);
    assert_eq!(
        snapshot.keys().cloned().collect::<Vec<_>>(),
        vec![
            PathBuf::from("bundle/adapters/source-extract.rhai"),
            PathBuf::from("bundle/adapters/source-prepare.rhai"),
            PathBuf::from("bundle/catalog.jsonld"),
            PathBuf::from("bundle/derivations/answer.rhai"),
            PathBuf::from("bundle/evidence.yaml"),
            PathBuf::from("bundle/fixtures/answer.yaml"),
            PathBuf::from(
                "bundle/public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json",
            ),
            PathBuf::from("bundle/schemas/facts.schema.yaml"),
            PathBuf::from("bundle/schemas/parameters.schema.yaml"),
            PathBuf::from("bundle/schemas/response.schema.yaml"),
            PathBuf::from("runtime.yaml"),
        ]
    );
    for (path, bytes) in snapshot {
        assert!(
            !bytes
                .windows(SECRET_CANARY.len())
                .any(|part| part == SECRET_CANARY.as_bytes()),
            "{} contains local secret material",
            path.display()
        );
        assert!(!path.to_string_lossy().contains("validation"));
    }
    fixture.assert_no_staging_residue();
}

#[test]
fn an_empty_publication_description_leaves_no_candidate() {
    let fixture = Fixture::new();
    fixture.declare_publication();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_EMPTY_DESCRIPTION", "1")
        .output()
        .expect("evidencectl build starts");

    assert_failed(
        &output,
        "an empty publication description must fail the build",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("publication"),
        "the refusal names the publication the bundle declares: {stderr}"
    );
    assert!(!fixture.output.exists());
    fixture.assert_no_staging_residue();
}

#[test]
fn a_bundle_without_publication_carries_no_catalog_description() {
    let fixture = Fixture::new();

    let output = fixture
        .command(&fixture.project, &fixture.target, &fixture.output)
        .env("FAKE_EVIDENCE_EMPTY_DESCRIPTION", "1")
        .output()
        .expect("evidencectl build starts");

    assert_success(&output, "build of a bundle that declares no publication");
    assert!(!fixture.output.join("bundle/catalog.jsonld").exists());
    fixture.assert_no_staging_residue();
}

#[test]
fn sqlite_extract_build_copies_the_statement_without_http_only_artifacts() {
    let fixture = Fixture::new();
    fixture.use_sqlite_source();

    let output = fixture.build();

    assert_success(&output, "SQLite extract production build");
    assert_eq!(
        fs::read_to_string(fixture.output.join("bundle/queries/source.sql")).unwrap(),
        "SELECT :reference <> '' AS allowed;\n"
    );
    assert!(fixture
        .output
        .join("bundle/adapters/source-extract.rhai")
        .is_file());
    assert!(!fixture
        .output
        .join("bundle/adapters/source-prepare.rhai")
        .exists());
    assert!(!fixture
        .output
        .join("bundle/schemas/parameters.schema.yaml")
        .exists());
    assert_eq!(fixture.steps(), ["check", "evaluate:fixtures/answer.yaml"]);
    fixture.assert_no_staging_residue();
}

#[test]
fn governed_public_keys_are_owned_by_the_complete_deployment_target() {
    let fixture = Fixture::new();
    let relative = Path::new("public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json");
    let target_key = fixture.target.join(relative);
    let bytes = fs::read(&target_key).expect("target public key");
    fs::remove_file(&target_key).expect("remove target public key");
    fs::create_dir(fixture.project.join("public-keys")).expect("project public key directory");
    fs::write(fixture.project.join(relative), bytes).expect("misplaced project public key");

    let output = fixture.build();

    assert_failed(&output, "a public key outside the deployment target");
    assert!(!fixture.output.exists());
    assert!(
        fixture.invocations().is_empty(),
        "missing target-owned key must fail before Evidence delegation"
    );
    fixture.assert_no_staging_residue();
}

#[test]
fn production_metadata_and_fixture_completeness_fail_before_runtime_delegation() {
    for label in [
        "missing-governance",
        "missing-stable-concept",
        "missing-fixture",
    ] {
        let fixture = Fixture::new();
        match label {
            "missing-governance" => fixture.remove_governance(),
            "missing-stable-concept" => {
                fixture.replace_in_question("    id: urn:example:concepts:allowed\n", "")
            }
            "missing-fixture" => fs::remove_file(fixture.project.join("fixtures/answer.yaml"))
                .expect("remove fixture"),
            _ => unreachable!(),
        }
        let output = fixture.build();
        assert_failed(&output, label);
        assert!(!fixture.output.exists());
        assert!(fixture.invocations().is_empty(), "{label} reached Evidence");
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn disposable_local_identifiers_fail_before_runtime_delegation() {
    for original in [
        "urn:example:requirements:allowed:v1",
        "urn:example:frameworks:allowed:v1",
        "urn:example:evidence-types:allowed:v1",
        "urn:example:disclosure-families:allowed",
        "urn:example:concepts:allowed",
    ] {
        let fixture = Fixture::new();
        fixture.replace_in_question(original, LOCAL_URI);
        let output = fixture.build();
        assert_failed(&output, "local identifier");
        assert!(!fixture.output.exists());
        assert!(fixture.invocations().is_empty());
        assert!(!stderr(&output).contains(LOCAL_URI));
    }
}

#[test]
fn plain_http_and_unauthenticated_sources_fail_before_runtime_delegation() {
    for (from, to) in [
        ("https://registry.invalid", "http://127.0.0.1:8088"),
        ("kind: static-authorization", "kind: none"),
    ] {
        let fixture = Fixture::new();
        fixture.replace_in_source(from, to);
        let output = fixture.build();
        assert_failed(&output, "insecure source");
        assert!(!fixture.output.exists());
        assert!(fixture.invocations().is_empty());
        fixture.assert_no_staging_residue();
    }
}

#[test]
fn unresolved_review_markers_and_unknown_target_fields_fail_closed() {
    let marker = Fixture::new();
    fs::write(
        marker.project.join("fixtures/answer.yaml"),
        "fixture: TODO(evidencectl)\n",
    )
    .expect("review marker");
    let marker_output = marker.build();
    assert_failed(&marker_output, "review marker");
    assert!(marker.invocations().is_empty());
    assert!(!marker.output.exists());
    assert_value_free(&marker_output);

    let unknown = Fixture::new();
    let mut governance = fs::read_to_string(&unknown.governance).unwrap();
    governance.push_str("deploymentGenerator: forbidden\n");
    fs::write(&unknown.governance, governance).unwrap();
    let unknown_output = unknown.build();
    assert_failed(&unknown_output, "unknown target field");
    assert!(unknown.invocations().is_empty());
    assert!(!unknown.output.exists());
    unknown.assert_no_staging_residue();
}

#[test]
fn semantic_authority_completeness_is_delegated_to_evidence() {
    let fixture = Fixture::new();
    let mut governance = fs::read_to_string(&fixture.governance).unwrap();
    let start = governance
        .find("authorityProfiles:")
        .expect("authority profile section");
    governance.truncate(start);
    governance.push_str("authorityProfiles:\n  incomplete: {}\n");
    fs::write(&fixture.governance, governance).unwrap();

    let output = fixture.build_failing("check");

    assert_failed(&output, "runtime-owned authority validation");
    assert_eq!(fixture.steps(), ["check"]);
    assert!(!fixture.output.exists());
    assert_value_free(&output);
    fixture.assert_no_staging_residue();
}

#[test]
fn every_referenced_fixture_is_delegated_and_one_failure_prevents_publication() {
    let fixture = Fixture::new();
    fixture.add_second_question();

    let passed = fixture.build();
    assert_success(&passed, "two-fixture build");
    assert_eq!(
        fixture.steps(),
        [
            "check",
            "evaluate:fixtures/answer.yaml",
            "evaluate:fixtures/second.yaml"
        ]
    );

    let failed = Fixture::new();
    failed.add_second_question();
    let output = failed.build_failing("fixture:fixtures/second.yaml");
    assert_failed(&output, "one rejected fixture");
    assert_eq!(
        failed.steps(),
        [
            "check",
            "evaluate:fixtures/answer.yaml",
            "evaluate:fixtures/second.yaml"
        ]
    );
    assert!(!failed.output.exists());
    assert_value_free(&output);
    failed.assert_no_staging_residue();
}

#[test]
fn identical_inputs_produce_identical_bundle_bytes_revision_and_stable_report_shape() {
    let fixture = Fixture::new();
    let first_output = fixture.root.join("candidate-one");
    let second_output = fixture.root.join("candidate-two");

    let first = fixture.build_with(&fixture.project, &fixture.target, &first_output);
    let second = fixture.build_with(&fixture.project, &fixture.target, &second_output);

    assert_success(&first, "first deterministic build");
    assert_success(&second, "second deterministic build");
    assert_eq!(
        snapshot(&first_output.join("bundle")),
        snapshot(&second_output.join("bundle"))
    );
    assert_report(&first, &first_output);
    assert_report(&second, &second_output);
    assert_eq!(reported_revision(&first), reported_revision(&second));
}

#[test]
fn termination_cancels_evidence_and_removes_only_current_build_staging() {
    for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
        let fixture = Fixture::new();
        let ready = fixture.root.join("blocked-evidence-ready");
        let unrelated = fixture.root.join(".evidencectl-build-unrelated");
        fs::create_dir(&unrelated).expect("unrelated staging");
        fs::write(unrelated.join("owned.txt"), "preserve me\n").expect("unrelated sentinel");

        let mut child = fixture
            .command(&fixture.project, &fixture.target, &fixture.output)
            .env("FAKE_EVIDENCE_BLOCK", "1")
            .env("FAKE_EVIDENCE_BLOCK_READY", &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("blocking evidencectl build starts");

        let ready_deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                child.try_wait().expect("poll blocking build").is_none(),
                "build exited before the fake Evidence process blocked"
            );
            assert!(
                Instant::now() < ready_deadline,
                "fake Evidence did not reach its blocking point"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let pid = rustix::process::Pid::from_raw(
            i32::try_from(child.id()).expect("evidencectl PID fits i32"),
        )
        .expect("evidencectl PID is positive");
        rustix::process::kill_process(pid, signal).expect("send signal to evidencectl build");

        let exit_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().expect("poll interrupted build").is_some() {
                break;
            }
            if Instant::now() >= exit_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("interrupted evidencectl build did not exit");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().expect("collect interrupted build");

        assert_failed(&output, "signal-interrupted build");
        assert_value_free(&output);
        assert!(!fixture.output.exists());
        assert_eq!(
            fs::read_to_string(unrelated.join("owned.txt")).unwrap(),
            "preserve me\n",
            "build cleaned unrelated staging"
        );
        fs::remove_dir_all(&unrelated).expect("remove test-owned unrelated staging");
        fixture.assert_no_staging_residue();
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
    target: PathBuf,
    governance: PathBuf,
    runtime: PathBuf,
    output: PathBuf,
    evidence: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary_root = workspace_root().join("target");
        fs::create_dir_all(&temporary_root).expect("workspace target");
        let temporary = tempfile::Builder::new()
            .prefix("production-build-")
            .tempdir_in(temporary_root)
            .expect("test tempdir");
        let root = temporary.path().to_path_buf();
        let project = root.join("project");
        let target = project.join("deployment-targets/production");
        for directory in [
            "selectors",
            "sources",
            "adapters",
            "schemas",
            "questions",
            "derivations",
            "fixtures",
        ] {
            fs::create_dir_all(project.join(directory)).expect("project directory");
        }
        fs::create_dir_all(target.join("public-keys")).expect("target directory");

        fs::write(
            project.join("source.openapi.yaml"),
            "openapi: 3.1.0\ninfo: {title: Neutral source, version: 1.0.0}\npaths: {}\n",
        )
        .expect("retained OpenAPI");
        fs::write(
            project.join("selectors/subject-reference-v1.yaml"),
            "maximumAggregateBytes: 128\nfields:\n  reference: {type: string, minimumBytes: 1, maximumBytes: 128}\n",
        )
        .expect("selector profile");
        fs::write(project.join("sources/registry.yaml"), SOURCE).expect("source");
        fs::write(
            target.join(
                "public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json",
            ),
            r#"{"kty":"EC","crv":"P-256","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#,
        )
        .expect("governed public key");
        fs::write(
            project.join("adapters/source-prepare.rhai"),
            "fn prepare(selectors, context) { #{query: [], body: #{reference: selectors[\"subject\"][\"values\"][\"reference\"]}} }\n",
        )
        .expect("prepare script");
        fs::write(
            project.join("adapters/source-extract.rhai"),
            "fn extract(source_response, context) { #{outcome: \"match\", facts: #{allowed: source_response[\"allowed\"]}} }\n",
        )
        .expect("extract script");
        fs::write(
            project.join("schemas/parameters.schema.yaml"),
            "type: object\nadditionalProperties: false\nproperties: {}\n",
        )
        .expect("parameters schema");
        fs::write(
            project.join("schemas/response.schema.yaml"),
            "type: object\nadditionalProperties: false\nrequired: [allowed]\nproperties:\n  allowed: {type: boolean}\n",
        )
        .expect("response schema");
        fs::write(
            project.join("schemas/facts.schema.yaml"),
            "type: object\nadditionalProperties: false\nrequired: [allowed]\nproperties:\n  allowed: {type: boolean}\n",
        )
        .expect("facts schema");
        fs::write(project.join("questions/answer.yaml"), question("answer")).expect("question");
        fs::write(
            project.join("derivations/answer.rhai"),
            "fn answer(facts, selectors, context) { #{allowed: facts[\"allowed\"]} }\n",
        )
        .expect("derivation");
        fs::write(
            project.join("fixtures/answer.yaml"),
            "fixture: neutral.answer/v1\n",
        )
        .expect("fixture");

        let governance = target.join("governance.yaml");
        fs::write(&governance, GOVERNANCE).expect("target governance");
        let runtime = target.join("runtime.yaml");
        fs::write(&runtime, TARGET_RUNTIME).expect("target runtime");

        let evidence = root.join("evidence");
        fs::write(&evidence, FAKE_EVIDENCE).expect("fake Evidence");
        let mut permissions = fs::metadata(&evidence).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&evidence, permissions).unwrap();

        Self {
            output: root.join("candidate"),
            log: root.join("evidence-invocations"),
            _temporary: temporary,
            root,
            project,
            target,
            governance,
            runtime,
            evidence,
        }
    }

    fn build(&self) -> Output {
        self.build_with(&self.project, &self.target, &self.output)
    }

    fn build_failing(&self, failure: &str) -> Output {
        self.command(&self.project, &self.target, &self.output)
            .env("FAKE_EVIDENCE_FAIL", failure)
            .output()
            .expect("evidencectl build starts")
    }

    fn build_with(&self, project: &Path, target: &Path, output: &Path) -> Output {
        self.command(project, target, output)
            .output()
            .expect("evidencectl build starts")
    }

    fn command(&self, project: &Path, target: &Path, output: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
        command
            .arg("build")
            .arg("--project")
            .arg(project)
            .arg("--target")
            .arg(target)
            .arg("--output")
            .arg(output)
            .env("EVIDENCE_BIN", &self.evidence)
            .env("FAKE_EVIDENCE_LOG", &self.log)
            .env(
                "FAKE_EVIDENCE_VERSION",
                registry_platform_buildinfo::DISPLAY_VERSION,
            )
            .env_remove("FAKE_EVIDENCE_FAIL")
            .env_remove("FAKE_EVIDENCE_EMPTY_DESCRIPTION");
        command
    }

    fn invocations(&self) -> Vec<Vec<String>> {
        let Ok(contents) = fs::read_to_string(&self.log) else {
            return Vec::new();
        };
        contents
            .split("===\n")
            .filter(|part| !part.is_empty())
            .map(|part| part.lines().map(str::to_owned).collect())
            .collect()
    }

    fn steps(&self) -> Vec<String> {
        self.invocations()
            .into_iter()
            .map(|args| {
                if let Some(index) = args.iter().position(|arg| arg == "--fixture") {
                    format!("evaluate:{}", args[index + 1])
                } else {
                    "check".to_owned()
                }
            })
            .collect()
    }

    fn replace_in_question(&self, from: &str, to: &str) {
        replace(&self.project.join("questions/answer.yaml"), from, to);
    }

    fn replace_in_source(&self, from: &str, to: &str) {
        replace(&self.project.join("sources/registry.yaml"), from, to);
    }

    fn use_sqlite_source(&self) {
        fs::create_dir(self.project.join("queries")).expect("query directory");
        fs::write(
            self.project.join("queries/source.sql"),
            "SELECT :reference <> '' AS allowed;\n",
        )
        .expect("statement");
        fs::write(self.project.join("sources/registry.yaml"), SQLITE_SOURCE)
            .expect("SQLite source");
        fs::write(
            self.project.join("adapters/source-extract.rhai"),
            "fn extract(source_response, context) { #{outcome: \"match\", facts: #{allowed: source_response[\"rows\"][0][\"allowed\"]}} }\n",
        )
        .expect("SQLite extract script");
        fs::write(
            self.project.join("schemas/response.schema.yaml"),
            "type: object\nadditionalProperties: false\nrequired: [rows]\nproperties:\n  rows:\n    type: array\n    minItems: 1\n    maxItems: 1\n    items:\n      type: object\n      additionalProperties: false\n      required: [allowed]\n      properties:\n        allowed: {type: boolean}\n",
        )
        .expect("SQLite response schema");
        let mut runtime = fs::read_to_string(&self.runtime).expect("target runtime");
        runtime.push_str(
            "sourceExtracts:\n  registry-snapshot:\n    path: /var/lib/evidence/registry.sqlite\n",
        );
        fs::write(&self.runtime, runtime).expect("runtime extract binding");
    }

    /// Declare a provider publication in the deployment target, the shape
    /// that makes `evidence render-discovery-description` produce a catalog
    /// description rather than nothing.
    fn declare_publication(&self) {
        let mut governance = fs::read_to_string(&self.governance).expect("target governance");
        governance.push_str(PUBLICATION);
        fs::write(&self.governance, governance).expect("target governance with publication");
    }

    fn remove_governance(&self) {
        let path = self.project.join("questions/answer.yaml");
        let mut contents = fs::read_to_string(&path).expect("question reads");
        let start = contents.find("governance:\n").expect("governance section");
        contents.truncate(start);
        fs::write(path, contents).expect("question without governance writes");
    }

    fn add_second_question(&self) {
        fs::write(
            self.project.join("questions/second.yaml"),
            question("second"),
        )
        .expect("second question");
        fs::write(
            self.project.join("derivations/second.rhai"),
            "fn answer(facts, selectors, context) { #{allowed: facts[\"allowed\"]} }\n",
        )
        .expect("second derivation");
        fs::write(
            self.project.join("fixtures/second.yaml"),
            "fixture: neutral.second/v1\n",
        )
        .expect("second fixture");
    }

    fn assert_no_staging_residue(&self) {
        fn collect(path: &Path, names: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(path).expect("staging scan directory") {
                let entry = entry.expect("staging scan entry");
                let entry_path = entry.path();
                let metadata = fs::symlink_metadata(&entry_path).expect("staging scan metadata");
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(".evidencectl-build-")
                    || name.starts_with(".evidencectl-build-validation-")
                {
                    names.push(entry_path.clone());
                }
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    collect(&entry_path, names);
                }
            }
        }
        let mut names = Vec::new();
        collect(&self.root, &mut names);
        assert!(
            names.is_empty(),
            "private staging residue remained: {names:?}"
        );
    }
}

fn question(id: &str) -> String {
    format!(
        r#"id: {id}
question: Is the governed condition satisfied?
purpose: eligibility
subject:
  role: subject
  selector: reference
  profile: subject-reference-v1
source:
  ref: registry
answers:
  - concept: allowed
    id: urn:example:concepts:allowed
    type: boolean
derivation: derivations/{id}.rhai
disclosure:
  allow: [allowed]
governance:
  requirement: urn:example:requirements:allowed:v1
  kind: criterion
  referenceFrameworks: [urn:example:frameworks:allowed:v1]
  evidenceType: urn:example:evidence-types:allowed:v1
  validitySeconds: 300
  observationTimezone: UTC
  fixtures: fixtures/{id}.yaml
  disclosureFamilies: [urn:example:disclosure-families:allowed]
"#
    )
}

fn replace(path: &Path, from: &str, to: &str) {
    let contents = fs::read_to_string(path).expect("replace source reads");
    assert!(contents.contains(from), "replacement source was present");
    fs::write(path, contents.replacen(from, to, 1)).expect("replacement writes");
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failed(output: &Output, label: &str) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn assert_value_free(output: &Output) {
    let mut diagnostic = output.stdout.clone();
    diagnostic.extend_from_slice(&output.stderr);
    for prohibited in [
        SECRET_CANARY,
        "synthetic-selector-canary",
        "source-value-canary",
    ] {
        assert!(
            !diagnostic
                .windows(prohibited.len())
                .any(|part| part == prohibited.as_bytes()),
            "build diagnostic exposed protected test material"
        );
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_report(output: &Output, candidate: &Path) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout,
        format!(
            "Bundle revision: {REVISION}\nCandidate: {}\nProvision secret:file/audit-hmac-key\nProvision secret:file/source-token\nProvision secret:file/subject-binding-hmac-key\nTarget runtime paths and deployment secret material remain unverified until `evidencectl doctor --project {}` and the target-host Evidence check.\n",
            candidate.display(),
            candidate.display(),
        )
    );
}

fn reported_revision(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Bundle revision: "))
        .expect("revision report")
        .to_owned()
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(path)
            .expect("snapshot directory")
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            let metadata = fs::symlink_metadata(&entry).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                visit(root, &entry, files);
            } else {
                files.insert(
                    entry.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

const SOURCE: &str = r#"transport: http-json
baseUrl: https://registry.invalid
posture: field-projected
authentication: {kind: static-authorization, tokenRef: 'secret:file/source-token'}
request:
  method: POST
  path: /v1/facts
  fixedHeaders: [{name: Accept, value: application/json}]
  selectorInputs:
    - role: subject
      alternatives:
        - {profile: subject-reference-v1, fields: [reference]}
  prepareScript: adapters/source-prepare.rhai
  adapterParameters: {}
  adapterParametersSchema: schemas/parameters.schema.yaml
  preparationLimits: {query: forbidden, jsonBody: required, maximumJsonDepth: 4, maximumCollectionItems: 8, maximumStringBytes: 128, maximumNormalizedBytes: 1024}
  projection: [/allowed]
  redirects: deny
  timeoutMilliseconds: 1000
  maximumResponseBytes: 4096
  concurrencyLimit: 1
responseSchema: schemas/response.schema.yaml
extractScript: adapters/source-extract.rhai
factSchema: schemas/facts.schema.yaml
"#;

const SQLITE_SOURCE: &str = r#"transport: sqlite-extract
posture: source-derived
extractProfile: registry-snapshot
maximumExtractAgeSeconds: 86400
request:
  statement: queries/source.sql
  columns: [{name: allowed, type: boolean}]
  selectorInputs:
    - role: subject
      alternatives:
        - {profile: subject-reference-v1, fields: [reference]}
  parameterBindings:
    reference: {kind: selector, role: subject, profile: subject-reference-v1, field: reference}
  projection: [/rows/*/allowed]
  maximumRows: 1
  maximumCellBytes: 8
  maximumStatementSteps: 10000
  timeoutMilliseconds: 1000
  maximumResponseBytes: 4096
  concurrencyLimit: 1
responseSchema: schemas/response.schema.yaml
extractScript: adapters/source-extract.rhai
factSchema: schemas/facts.schema.yaml
"#;

const GOVERNANCE: &str = r#"version: 1
assuranceProfile: production
service: {providerId: urn:example:providers:evidence, trustDomain: urn:example:trust-domains:evidence}
issuer: {id: urn:example:issuers:evidence}
authentication:
  kind: oidc-access-token
  issuer: https://issuer.invalid
  audiences: [evidence]
  tokenTypes: [at+jwt]
  algorithms: [ES256]
  jwksUri: https://issuer.invalid/.well-known/jwks.json
  principalClaim: sub
  requesterTagsClaim: evidence_tags
  evidenceAudienceClaim: evidence_audience
  grantIdClaim: evidence_grant_id
  grantAuthorityClaim: evidence_authority
  maximumTokenLifetimeSeconds: 300
  revokedKeyIds: []
audit: {format: keyed-jsonl, hashSecretRef: 'secret:file/audit-hmac-key', hashKeyVersion: 1, failClosed: true}
subjectBinding: {secretRef: 'secret:file/subject-binding-hmac-key', keyVersion: 1}
rateLimits: {requestsPerPrincipalPerMinute: 60, burstPerPrincipal: 10, failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 10}
signing:
  format: flattened-jws-json
  algorithm: ES256
  activePublicJwkFile: public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json
  publishedPublicJwkFiles: []
  revokedKeyIds: []
  jwksPath: /.well-known/evidence/jwks.json
  maximumAssertionValiditySeconds: 300
  verifierClockSkewSeconds: 30
responseFormats: [signed-jws]
authorityProfiles:
  requester:
    kind: statutory
    requesterTags: [requester]
    grants:
      - requirement: urn:example:requirements:allowed:v1
        purpose: eligibility
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws]
        subjects: [{role: subject, selectorProfile: subject-reference-v1, valueOrigin: request}]
"#;

const PUBLICATION: &str = r#"publication:
  serviceId: urn:example:services:evidence
  title: Governed Evidence service
  description: Governed minimum-disclosure Evidence service
  endpointUrl: https://evidence.invalid
  jurisdictions: [urn:example:jurisdictions:governed]
"#;

const TARGET_RUNTIME: &str = r#"version: 1
bundleDirectory: /srv/evidence/candidate/bundle
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 8
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 10000
secretProviders:
  file: {root: /run/secrets/evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
auditStorage: {path: /var/lib/evidence/audit.jsonl, maximumFileBytes: 1048576}
outboundTls: {systemRoots: true, trustProfiles: {}}
"#;

const FAKE_EVIDENCE: &str = r#"#!/bin/sh
set -eu

if [ "${1:-}" = '--version' ]; then
  printf 'evidence %s\n' "$FAKE_EVIDENCE_VERSION"
  exit 0
fi

if [ "${1:-}" = 'render-discovery-description' ]; then
  if [ "${FAKE_EVIDENCE_EMPTY_DESCRIPTION:-}" != '1' ]; then
    printf '{}\n'
  fi
  exit 0
fi

for arg in "$@"; do
  printf '%s\n' "$arg" >> "$FAKE_EVIDENCE_LOG"
done
printf '%s\n' '===' >> "$FAKE_EVIDENCE_LOG"

if [ "${FAKE_EVIDENCE_BLOCK:-}" = '1' ]; then
  printf '%s\n' ready > "$FAKE_EVIDENCE_BLOCK_READY"
  exec sleep 300
fi

fixture=''
previous=''
for arg in "$@"; do
  if [ "$previous" = '--fixture' ]; then fixture=$arg; fi
  previous=$arg
done

failure=${FAKE_EVIDENCE_FAIL:-}
if [ "$failure" = 'check' ] && [ -z "$fixture" ]; then
  printf '%s\n' 'production-build-secret-canary synthetic-selector-canary source-value-canary' >&2
  exit 1
fi
if [ "$failure" = "fixture:$fixture" ]; then
  printf '%s\n' 'production-build-secret-canary synthetic-selector-canary source-value-canary' >&2
  exit 1
fi

if [ -z "$fixture" ]; then
  printf '%s\n' 'Evidence bundle sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa passed check (2 requirements)'
else
  printf '%s\n' 'Evidence fixture passed (1 evaluated cases)'
fi
"#;
